/**
 * Trust core — the single copy of canonical JSON, ES256 signing, and trust
 * thresholds that used to be duplicated in agentpay, bsvbounties, and the
 * x402-gateway. If this file changes, behavior changes everywhere by design.
 *
 * A profile is signed exactly like an agentpay attestation: ECDSA P-256 /
 * SHA-256 over the canonical JSON (sorted keys, raw IEEE P1363 signature,
 * base64url) so any consumer can verify a verdict offline.
 */

// ---------- canonical JSON ----------

/** Deterministic JSON: object keys sorted, arrays in order. */
export function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(record[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

// ---------- base64url ----------

export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---------- signing keys (ES256) ----------

export const TRUST_VERSION = 1;
export const TRUST_ISSUER = "trust.entangleit.com";
export const TRUST_ALG = "ES256";

export interface TrustSigningKey {
  privateKey: CryptoKey;
  publicJwk: JsonWebKey;
  keyId: string;
}

export interface KeyEnv {
  TRUST_KEY_JWK?: string;
}

let keyCache: { source: string; key: TrustSigningKey | null } | null = null;

/** RFC 7638-style thumbprint over the required public JWK members. */
export async function signingKeyId(publicJwk: JsonWebKey): Promise<string> {
  const canonical = JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

/** Parse TRUST_KEY_JWK (private JWK JSON) into a signing key. Cached. */
export async function loadSigningKey(env: KeyEnv): Promise<TrustSigningKey | null> {
  const source = env.TRUST_KEY_JWK;
  if (!source) return null;
  if (keyCache && keyCache.source === source) return keyCache.key;
  try {
    const jwk = JSON.parse(source) as JsonWebKey;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d) {
      keyCache = { source, key: null };
      return null;
    }
    const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const publicJwk: JsonWebKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    const key: TrustSigningKey = { privateKey, publicJwk, keyId: await signingKeyId(publicJwk) };
    keyCache = { source, key };
    return key;
  } catch {
    keyCache = { source, key: null };
    return null;
  }
}

export async function trustPublicKey(env: KeyEnv): Promise<{ alg: string; keyId: string; publicJwk: JsonWebKey } | null> {
  const key = await loadSigningKey(env);
  if (!key) return null;
  return { alg: TRUST_ALG, keyId: key.keyId, publicJwk: key.publicJwk };
}

// ---------- profile types ----------

export type TrustLevel = "new" | "building" | "proven" | "trusted" | "elite";

export const LEVELS: TrustLevel[] = ["new", "building", "proven", "trusted", "elite"];

export function levelIndex(level: TrustLevel): number {
  const i = LEVELS.indexOf(level);
  return i < 0 ? 0 : i;
}

export function levelAt(index: number): TrustLevel {
  return LEVELS[Math.max(0, Math.min(LEVELS.length - 1, Math.round(index)))]!;
}

export interface TrustTerms {
  /** Multiplier on an approval threshold (only ever loosens; never uncaps). */
  approvalMultiplier: number;
  /** Bond discount in bps when the subject may waive part of a worker bond. */
  bondDiscountBps: number;
  /** Ceiling a seller may discount for this subject, in bps. */
  discountCeilingBps: number;
}

export const TERMS: Record<TrustLevel, TrustTerms> = {
  new: { approvalMultiplier: 1, bondDiscountBps: 0, discountCeilingBps: 0 },
  building: { approvalMultiplier: 1, bondDiscountBps: 0, discountCeilingBps: 0 },
  proven: { approvalMultiplier: 2, bondDiscountBps: 5000, discountCeilingBps: 1000 },
  trusted: { approvalMultiplier: 3, bondDiscountBps: 10000, discountCeilingBps: 2500 },
  elite: { approvalMultiplier: 4, bondDiscountBps: 10000, discountCeilingBps: 5000 },
};

export type BandFlag = "routine" | "review" | "hold";

export interface TrustBand {
  flag: BandFlag;
  /** Jev's calibrated probability (0-1) that the pattern is harmful. */
  probability: number;
  model?: string;
}

export function termsFor(level: TrustLevel, band?: TrustBand | null): TrustTerms {
  // Advisory only: a "hold" band steps the terms down one level. It can never
  // grant eligibility, and it can never raise terms. No answer = no change.
  const effective = band?.flag === "hold" ? levelAt(levelIndex(level) - 1) : level;
  return { ...TERMS[effective] };
}

export interface SpendMetrics {
  settledPayments: number;
  distinctServices: number;
  /** Distinct on-chain payees (anti-wash; absent when the issuer cannot see them). */
  distinctPayTo?: number;
  spentCents: number;
  refundedCents: number;
  bountyPayouts?: number;
  earnedCents?: number;
  firstPaymentAt?: string | null;
  lastPaymentAt?: string | null;
}

export interface WorkMetrics {
  score: number;
  provisional: boolean;
  slashes: number;
  /** Settled jobs completed (from observations when the source exposes them). */
  completed: number;
  verifyPassRate?: number | null;
  tier?: string;
  verified?: boolean;
}

export interface MarketMetrics {
  /** Distinct paid services the subject bought from. */
  services: number;
  /** Settled meter calls seen across gateways/markets. */
  calls: number;
  /** Lost disputes or shown-fraud events. */
  disputesLost: number;
}

export interface TrustProfileAxes {
  spend?: SpendMetrics | null;
  work?: WorkMetrics | null;
  market?: MarketMetrics | null;
}

export interface TrustProfile {
  v: number;
  iss: string;
  /** Canonical subject the profile is issued for. */
  sub: string;
  /** Every subject merged into this profile (bindings can add more later). */
  members: string[];
  issuedAt: string;
  expiresAt: string;
  level: TrustLevel;
  score: number;
  confidence: number;
  axes: TrustProfileAxes;
  terms: TrustTerms;
  reasons: string[];
  band?: TrustBand;
}

export interface SignedProfile {
  profile: TrustProfile;
  signature: string;
  keyId: string;
  alg: string;
}

export async function signProfile(env: KeyEnv, profile: TrustProfile): Promise<SignedProfile | null> {
  const key = await loadSigningKey(env);
  if (!key) return null;
  const bytes = new TextEncoder().encode(stableStringify(profile));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, bytes);
  return {
    profile,
    signature: toBase64Url(new Uint8Array(sig)),
    keyId: key.keyId,
    alg: TRUST_ALG,
  };
}

export async function verifyProfile(
  publicJwk: JsonWebKey,
  profile: TrustProfile,
  signature: string,
): Promise<boolean> {
  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const sig = fromBase64Url(signature) as unknown as BufferSource;
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      sig,
      new TextEncoder().encode(stableStringify(profile)),
    );
  } catch {
    return false;
  }
}

// ---------- thresholds: one source of truth ----------
// These are the exact gates that shipped in agentpay/bsvbounties/x402-gateway.
// Changing a constant here changes every consumer on its next deploy.

export const TRUST_ATTEST_MIN_PAYMENTS = 10;
export const TRUST_ATTEST_MIN_SERVICES = 3;
export const TRUST_ATTEST_MIN_SPENT_CENTS = 50;
export const TRUST_ATTEST_MIN_WALLET_AGE_MS = 7 * 86_400_000;
export const TRUST_REPUTATION_MIN_SCORE = 650;

/** Extra bars for the ratcheted levels (checked only after both axes verify). */
export const LEVEL_THRESHOLDS = {
  trusted: { payments: 50, payees: 10, spentCents: 500, completed: 5, passRate: 0.9, ageDays: 30 },
  elite: { payments: 200, payees: 25, spentCents: 2500, completed: 20, passRate: 0.95, ageDays: 90 },
} as const;

export interface GateDecision {
  eligible: boolean;
  reason: string;
}

/**
 * Spend axis: does verified payment history qualify for a fast-path?
 * Mirrors bounties' trustGateForClaim and the gateway's discount gate.
 * Fail closed on missing or malformed metrics.
 */
export function spendVerified(metrics: SpendMetrics | null | undefined, nowMs = Date.now()): GateDecision {
  if (!metrics || typeof metrics !== "object") return { eligible: false, reason: "no_attestation" };
  const m = metrics;
  if (typeof m.settledPayments !== "number" || typeof m.distinctServices !== "number") {
    return { eligible: false, reason: "bad_metrics" };
  }
  if (m.settledPayments < TRUST_ATTEST_MIN_PAYMENTS) return { eligible: false, reason: "too_few_payments" };
  if (m.distinctServices < TRUST_ATTEST_MIN_SERVICES) return { eligible: false, reason: "too_few_services" };
  // Counterparty diversity is the max over services (off-chain settlement,
// where the service IS the counterparty) and on-chain payees. Requiring
// on-chain payees outright would exclude all off-chain rail spend — the
// exact case tested here: 4 services, settled through agentpay, payTo null.
  const counterparties = Math.max(
    Number(m.distinctServices ?? 0),
    typeof m.distinctPayTo === "number" ? m.distinctPayTo : 0,
  );
  if (counterparties < TRUST_ATTEST_MIN_SERVICES) {
    return { eligible: false, reason: "too_few_payees" };
  }
  if ((m.spentCents ?? 0) < TRUST_ATTEST_MIN_SPENT_CENTS) return { eligible: false, reason: "spend_too_low" };
  if (typeof m.firstPaymentAt === "string" && m.firstPaymentAt) {
    const first = Date.parse(m.firstPaymentAt);
    if (Number.isFinite(first) && nowMs - first < TRUST_ATTEST_MIN_WALLET_AGE_MS) {
      return { eligible: false, reason: "wallet_too_new" };
    }
  }
  if ((m.refundedCents ?? 0) > 0) return { eligible: false, reason: "has_refunds" };
  return { eligible: true, reason: "trusted_spender" };
}

/**
 * Work axis: does reputation qualify for a fast-path?
 * Mirrors agentpay's decidePayTrust. Fail closed on provisional or slashes.
 */
export function workVerified(work: WorkMetrics | null | undefined): GateDecision {
  if (!work || typeof work.score !== "number") return { eligible: false, reason: "no_reputation" };
  if (work.provisional) return { eligible: false, reason: "provisional" };
  if ((work.slashes ?? 0) > 0) return { eligible: false, reason: "has_slashes" };
  if (work.score < TRUST_REPUTATION_MIN_SCORE) return { eligible: false, reason: "score_too_low" };
  return { eligible: true, reason: "trusted_worker" };
}