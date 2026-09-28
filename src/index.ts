/**
 * EntangleIT Trust worker — https://entangleit.com/trust.
 *
 * One signed profile that turns verified history into terms:
 *   GET  /v1/profile/:subject   signed profile (free, rate-limited)
 *   POST /profile               x402 pay-per-lookup (5 sats, BSV mainnet)
 *   POST /mcp                   remote MCP server for agents
 *   POST /v1/ingest             internal signal push (x-trust-internal)
 *   POST /v1/reconcile          internal pull from agentpay D1 + bounties
 *   GET  /p/:subject            public profile page + embeddable badge
 */
import { Hono } from "hono";
import type { Context } from "hono";
import { badgeSvg, profilePage } from "./badge.ts";
import { handleStripeEvent } from "./billing.ts";
import {
  TRUST_ALG,
  levelIndex,
  signProfile,
  signingKeyId,
  stableStringify,
  trustPublicKey,
  verifyProfile,
  type SignedProfile,
  type TrustBand,
  type TrustLevel,
  type TrustProfile,
} from "./core.ts";
import { renderDocs, renderLanding } from "./docs.ts";
import {
  attestationObservation,
  ingestObservation,
  isAttestationLike,
  marketFromObservations,
  resolveMembers,
  spendFromObservations,
  verifySignedObject,
  workFromObservations,
} from "./ingest.ts";
import type { ObservationInput } from "./store.ts";
import { handleMessage, SERVER_INFO, type ToolContext } from "./mcp.ts";
import { PLANS, planById } from "./plans.ts";
import { allowDaily, allowRate } from "./rate.ts";
import { mountRedirect, routePath } from "./routes.ts";
import { computeProfile, PROFILE_TTL_MS_DEFAULT, RATCHET_DAYS_DEFAULT } from "./score.ts";
import { fetchAgentpayPublicKey, reconcile, type SourceEnv } from "./source.ts";
import { createCheckoutSession, parseEvent, stripeConfigured, verifyWebhookSignature, type StripeEnv } from "./stripe.ts";
import { d1Store, memoryStore, type D1Like, type TrustStore } from "./store.ts";
import {
  arcBroadcast,
  b64decodeJson,
  b64encodeJson,
  buildRequirements,
  BSV_NETWORK,
  claimPaymentTxid,
  DEFAULT_ARC_URL,
  releasePaymentTxid,
  verifyBsvPayment,
  type BsvPaymentPayload,
  type ReplayKV,
} from "./x402.ts";

export interface Env extends StripeEnv, SourceEnv {
  DB?: D1Like;
  METER?: ReplayKV;
  ORACLE?: { fetch(input: Request): Promise<Response> };
  ORACLE_URL?: string;
  ORACLE_GATEWAY_KEY?: string;
  HIGH_VOLUME_PAYMENTS?: string;
  WORKERS_DEV_BASE?: string;
  PRICE_SATS?: string;
  PAY_TO?: string;
  ARC_URL?: string;
  ARC_API_KEY?: string;
  FREE_DAILY_CALLS?: string;
  RATE_LIMIT_PER_MIN?: string;
  PROFILE_TTL_MS?: string;
  CACHE_TTL_MS?: string;
  RATCHET_DAYS?: string;
  RECONCILE_LIMIT?: string;
  TRUST_KEY_JWK?: string;
  TRUST_INGEST_SECRET?: string;
  TRUST_ADMIN_TOKEN?: string;
}

const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers":
    "content-type, authorization, mcp-session-id, mcp-protocol-version, payment-signature, x-trust-internal, x-oracle-gateway-key",
  "access-control-expose-headers": "payment-required, payment-response",
};

function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(data, { status, headers: { ...CORS, ...headers } });
}

function html(body: string): Response {
  return new Response(body, { headers: { ...CORS, "content-type": "text/html; charset=utf-8" } });
}

function num(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

function publicBase(env: Env): string {
  return (env.PUBLIC_BASE ?? "").trim().replace(/\/$/, "") || "https://entangleit.com/trust";
}

function freeDaily(env: Env): number {
  return num(env.FREE_DAILY_CALLS, 5);
}

function cacheTtl(env: Env): number {
  return Math.max(1_000, num(env.CACHE_TTL_MS, 300_000));
}

/** D1 in production; one in-memory store per env for local dev and tests. */
function storeFor(env: Env): TrustStore {
  if (env.DB) return d1Store(env.DB);
  const holder = env as Env & { __memory?: TrustStore };
  holder.__memory ??= memoryStore();
  return holder.__memory;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const SUBJECT_RE = /^(wallet|account|key):[A-Za-z0-9:_.@-]{1,160}$/;

function subjectFrom(raw: string | undefined): string | null {
  if (!raw) return null;
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  const trimmed = decoded.trim();
  return SUBJECT_RE.test(trimmed) ? trimmed : null;
}

function isInternal(req: Request, env: Env): boolean {
  const secret = (env.TRUST_INGEST_SECRET ?? "").trim();
  return secret.length > 0 && (req.headers.get("x-trust-internal") ?? "") === secret;
}

async function accountFor(req: Request, env: Env, store: TrustStore): Promise<{ account: ToolContext["account"]; unlimited: boolean }> {
  const auth = req.headers.get("authorization") ?? "";
  const token = auth.replace(/^bearer\s+/i, "").trim();
  if (token) {
    const operator = (env.TRUST_ADMIN_TOKEN ?? "").trim();
    if (operator && token === operator) {
      return { account: await store.ensureAccount("admin:operator", null, 0), unlimited: true };
    }
    const id = `acct:${await sha256Hex(new TextEncoder().encode(token))}`;
    const account = await store.getAccount(id);
    if (!account) throw Object.assign(new Error("unknown token"), { status: 401 });
    return { account, unlimited: false };
  }
  const ip = req.headers.get("cf-connecting-ip") ?? "0.0.0.0";
  const id = `anon:${(await sha256Hex(new TextEncoder().encode(ip))).slice(0, 24)}`;
  return { account: await store.ensureAccount(id, null, 0), unlimited: false };
}

// ---------- Jev advisory band (gray zone only) ----------

interface BandState {
  spendEligible: boolean;
  workEligible: boolean;
  settledPayments: number;
  distinctServices: number;
  spentCents: number;
  refunds: number;
  reputationScore: number | null;
  provisional: boolean | null;
  slashes: number | null;
  completed: number;
  accountAgeDays: number;
}

function needsBand(state: BandState, highVolume: number): boolean {
  // Only the boundary between building and proven, or unusual velocity,
  // deserves a smoke alarm. Verified-and-quiet accounts are not asked about.
  if (state.spendEligible !== state.workEligible) return true;
  if (state.spendEligible && state.workEligible && state.settledPayments >= highVolume) return true;
  return false;
}

async function askOracle(env: Env, state: BandState): Promise<TrustBand | null> {
  if (!env.ORACLE_URL && !env.ORACLE) return null;
  if (!needsBand(state, num(env.HIGH_VOLUME_PAYMENTS, 100))) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  try {
    const body = JSON.stringify({
      content: JSON.stringify(state),
      questions: [
        {
          id: "fraud_risk",
          type: "score",
          question:
            "0 = consistent with honest verified activity. 100 = clear fraud or sybil pattern " +
            "(fake counterparties, wash activity, refund abuse, impossible velocity).",
          min: 0,
          max: 100,
        },
      ],
    });
    const headers: Record<string, string> = { "content-type": "application/json" };
    const gatewayKey = (env.ORACLE_GATEWAY_KEY ?? "").trim();
    if (gatewayKey) headers["x-oracle-gateway-key"] = gatewayKey;
    let res: Response;
    if (env.ORACLE) {
      res = await env.ORACLE.fetch(
        new Request("https://decision-oracle/decision", {
          method: "POST",
          headers,
          body,
          signal: controller.signal,
        }),
      );
    } else {
      res = await fetch(`${(env.ORACLE_URL ?? "").replace(/\/$/, "")}/decision`, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });
    }
    if (!res.ok) return null;
    const out = (await res.json()) as { results?: Array<{ id?: string; value?: unknown }>; model?: string };
    const value = Number(out.results?.[0]?.value);
    if (!Number.isFinite(value)) return null;
    const probability = Math.max(0, Math.min(1, value / 100));
    const flag = probability >= 0.7 ? "hold" : probability >= 0.4 ? "review" : "routine";
    return { flag, probability: Number(probability.toFixed(2)), ...(out.model ? { model: out.model } : {}) };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- profile assembly ----------

async function profileFor(env: Env, store: TrustStore, subject: string): Promise<SignedProfile | null> {
  const now = Date.now();
  const cached = await store.getVerdict(subject);
  if (cached && cached.expires_at > now) {
    try {
      return JSON.parse(cached.profile_json) as SignedProfile;
    } catch {
      // fall through and recompute
    }
  }

  const bindings = await store.listBindings();
  const members = resolveMembers(bindings, subject);
  const observations = await store.listObservations(members, 500);
  const spend = spendFromObservations(observations);
  const work = workFromObservations(observations);
  const market = marketFromObservations(observations);

  let storedLevel: TrustLevel | undefined;
  let lastUpgradeAt: number | undefined;
  for (const member of members) {
    const state = await store.getState(member);
    if (!state) continue;
    const level = state.level as TrustLevel;
    if (!storedLevel || levelIndex(level) > levelIndex(storedLevel)) storedLevel = level;
    if (!lastUpgradeAt || state.updated_at > lastUpgradeAt) lastUpgradeAt = state.updated_at;
  }

  const state: BandState = {
    spendEligible: Boolean(spend && spend.settledPayments >= 10),
    workEligible: Boolean(work && work.score >= 650 && !work.provisional && work.slashes === 0),
    settledPayments: spend?.settledPayments ?? 0,
    distinctServices: spend?.distinctServices ?? 0,
    spentCents: spend?.spentCents ?? 0,
    refunds: spend?.refundedCents ?? 0,
    reputationScore: work?.score ?? null,
    provisional: work ? work.provisional : null,
    slashes: work?.slashes ?? null,
    completed: work?.completed ?? 0,
    accountAgeDays: spend?.firstPaymentAt
      ? Math.max(0, Math.round((now - Date.parse(spend.firstPaymentAt)) / 86_400_000))
      : 0,
  };
  const band = await askOracle(env, state);

  const profile = computeProfile({
    subject,
    members,
    spend,
    work,
    market,
    now,
    storedLevel,
    lastUpgradeAt,
    ratchetDays: num(env.RATCHET_DAYS, RATCHET_DAYS_DEFAULT),
    ttlMs: num(env.PROFILE_TTL_MS, PROFILE_TTL_MS_DEFAULT),
    band,
  });

  const signed = await signProfile(env, profile);
  if (!signed) return null;

  // Persist ratchet state only for members whose level actually changed, so
  // updated_at means "when the level last moved" and the window is honest.
  for (const member of members) {
    await store.touchSubject(member, now);
    const existing = await store.getState(member);
    if (!existing || existing.level !== profile.level) {
      await store.setState(member, profile.level, now);
    }
  }
  await store.saveVerdict(subject, JSON.stringify(signed), now + cacheTtl(env));
  return signed;
}

// ---------- bindings ----------

async function verifyChallenge(jwk: JsonWebKey, message: string, signature: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const bin = atob(signature.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (signature.length % 4)) % 4));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      bytes,
      new TextEncoder().encode(message),
    );
  } catch {
    return false;
  }
}

let agentpayKeyCache: { at: number; key: { publicJwk: JsonWebKey; keyId: string } | null } | null = null;

async function agentpayKey(env: Env): Promise<{ publicJwk: JsonWebKey; keyId: string } | null> {
  if (agentpayKeyCache && Date.now() - agentpayKeyCache.at < 3_600_000) return agentpayKeyCache.key;
  const key = await fetchAgentpayPublicKey(env);
  agentpayKeyCache = { at: Date.now(), key };
  return key;
}

interface BindResult {
  ok: boolean;
  error?: string;
  a?: string;
  b?: string;
  proof?: string;
}

async function doBind(
  env: Env,
  store: TrustStore,
  args: Record<string, unknown>,
  opts: { internal: boolean; now?: number } = { internal: false },
): Promise<BindResult> {
  const other = typeof args.other === "string" ? args.other.trim() : "";
  if (!/^(wallet|account):[A-Za-z0-9:_.@-]{1,160}$/.test(other)) {
    return { ok: false, error: "other must be wallet:<id> or account:<n>" };
  }

  // Operator-assisted binding: with the shared secret an operator may assert
  // a known key linkage (e.g. a BSV-native secp256k1 key that cannot sign the
  // P-256 challenge, or a wallet whose agentpay token is unavailable).
  // Recorded as proof "operator" so it is auditable and never mistaken for a
  // cryptographic binding; self-serve challenge bindings are unchanged.
  const operatorKey = typeof args.key === "string" ? args.key.trim() : "";
  if (opts.internal && operatorKey) {
    if (!/^key:[A-Za-z0-9:_.@-]{1,160}$/.test(operatorKey)) {
      return { ok: false, error: "key must be key:<subject>" };
    }
    const now = opts.now ?? Date.now();
    await store.touchSubject(operatorKey, now);
    await store.touchSubject(other, now);
    await store.addBinding({
      a: operatorKey,
      b: other,
      proof: "operator",
      evidence: "x-trust-internal",
      bound_at: now,
    });
    return { ok: true, a: operatorKey, b: other, proof: "operator" };
  }

  const jwk = args.jwk as JsonWebKey | undefined;
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    return { ok: false, error: "jwk must be a public P-256 key" };
  }
  const keySubject = `key:${await signingKeyId(jwk)}`;
  const nonce = typeof args.nonce === "string" ? args.nonce.trim() : "";
  const signature = typeof args.signature === "string" ? args.signature : "";
  if (!nonce || !signature) return { ok: false, error: "nonce and signature are required" };

  const nonceKey = `trust:bind:${nonce}`;
  if (env.METER) {
    const seen = await env.METER.get(nonceKey);
    if (!seen) return { ok: false, error: "unknown or already-used nonce" };
  }
  const valid = await verifyChallenge(jwk, `bind:${keySubject}:${other}:${nonce}`, signature);
  if (!valid) return { ok: false, error: "bad challenge signature" };
  if (env.METER) await env.METER.delete(nonceKey);

  let proof = "challenge";
  let evidence = JSON.stringify({ alg: TRUST_ALG, jwk });
  if (other.startsWith("wallet:")) {
    const attestation = args.attestation;
    const attestationSignature = typeof args.attestationSignature === "string" ? args.attestationSignature : "";
    if (!isAttestationLike(attestation) || !attestationSignature) {
      return { ok: false, error: "wallet bindings require a signed agentpay attestation (attestation + attestationSignature)" };
    }
    const key = await agentpayKey(env);
    if (!key) return { ok: false, error: "agentpay attestation key unavailable" };
    if (!(await verifySignedObject(key.publicJwk, attestation, attestationSignature))) {
      return { ok: false, error: "bad attestation signature" };
    }
    if (attestation.wallet !== other.slice("wallet:".length)) {
      return { ok: false, error: "attestation wallet does not match the subject" };
    }
    if (attestation.sub !== keySubject) {
      return { ok: false, error: "attestation sub must equal the key subject (request the attestation with sub=<key id>)" };
    }
    proof = "agentpay:attestation";
    evidence = JSON.stringify({ alg: TRUST_ALG, jwk, keyId: key.keyId, attestationIssuedAt: attestation.issuedAt });
  } else if (other.startsWith("account:") && !opts.internal) {
    return { ok: false, error: "account bindings are operator-assisted in v1 (x-trust-internal header required)" };
  }

  const now = opts.now ?? Date.now();
  await store.touchSubject(keySubject, now);
  await store.touchSubject(other, now);
  await store.addBinding({ a: keySubject, b: other, proof, evidence, bound_at: now });
  return { ok: true, a: keySubject, b: other, proof };
}

// ---------- x402 paid profile ----------

async function handlePaidProfile(c: Context<{ Bindings: Env }>): Promise<Response> {
  const env = c.env;
  const base = publicBase(env);
  const price = num(env.PRICE_SATS, 5);
  const payTo = (env.PAY_TO ?? "").trim();
  const url = `${base}/profile`;

  let body: Record<string, unknown>;
  try {
    body = (await c.req.json()) as Record<string, unknown>;
  } catch {
    return json({ error: { code: "invalid_json", message: "body must be valid JSON" } }, 400);
  }
  const subject = subjectFrom(typeof body.subject === "string" ? body.subject : "");
  if (!subject) {
    return json({ error: { code: "invalid_subject", message: "subject must look like wallet:<id>, account:<n>, or key:<thumbprint>" } }, 400);
  }

  const store = storeFor(env);
  const viaInternal = isInternal(c.req.raw, env);
  let payer = "";
  let txid = "";

  if (price > 0 && !viaInternal) {
    if (!payTo) {
      return json({ error: { code: "pay_to_not_configured", message: "PAY_TO is not configured" } }, 503);
    }
    const requirements = buildRequirements({
      url,
      description: `EntangleIT Trust/profile: signed terms for ${price} sats`,
      satoshis: price,
      payTo,
      arcUrl: env.ARC_URL ?? DEFAULT_ARC_URL,
    });
    const signature = c.req.header("PAYMENT-SIGNATURE");
    if (!signature) {
      return json(
        {
          error: { code: "payment_required", message: `This lookup costs ${price} sats. Retry with a PAYMENT-SIGNATURE proof.` },
          priceSats: price,
          payTo,
          network: BSV_NETWORK,
          resource: url,
        },
        402,
        { "PAYMENT-REQUIRED": b64encodeJson(requirements) },
      );
    }
    let payload: BsvPaymentPayload;
    try {
      payload = b64decodeJson<BsvPaymentPayload>(signature);
    } catch {
      return json({ success: false, errorReason: "invalid_payload", network: BSV_NETWORK }, 402);
    }
    const verified = await verifyBsvPayment(requirements, payload);
    if (!verified.success) return json({ ...verified, network: BSV_NETWORK }, 402);
    if (!(await claimPaymentTxid(env, verified.txid))) {
      return json({ success: false, errorReason: "payment_already_used", network: BSV_NETWORK }, 402);
    }

    const signed = await profileFor(env, store, subject);
    if (!signed) {
      await releasePaymentTxid(env, verified.txid);
      return json({ error: { code: "signing_not_configured", message: "TRUST_KEY_JWK is not configured" } }, 503);
    }
    try {
      const broadcast = await arcBroadcast(env, verified.txHex);
      txid = broadcast.txid || verified.txid;
    } catch (e) {
      await releasePaymentTxid(env, verified.txid);
      const detail = String((e as Error)?.message ?? e).slice(0, 300);
      return json(
        { error: { code: "settlement_failed", message: "payment could not be settled; nothing was charged" }, detail },
        502,
      );
    }
    payer = verified.payer;
    await store.recordCall({ id: crypto.randomUUID(), account_id: `x402:${payer}`, kind: "profile", subject, created_at: Date.now() });
    return json(signed, 200, {
      "PAYMENT-RESPONSE": b64encodeJson({ success: true, payer, transaction: txid, network: BSV_NETWORK, priceSats: price }),
    });
  }

  const signed = await profileFor(env, store, subject);
  if (!signed) return json({ error: { code: "signing_not_configured", message: "TRUST_KEY_JWK is not configured" } }, 503);
  return json(signed);
}

// ---------- manifest ----------

function manifest(env: Env): unknown {
  const base = publicBase(env);
  const price = num(env.PRICE_SATS, 5);
  return {
    name: "EntangleIT Trust",
    tagline: "Signed trust profiles and terms for agents",
    description:
      "Merges verified spend (agentpay) and verified work (BSVBounties) into one signed profile: level, score, " +
      "and the terms it unlocks — approval multiplier, bond discount, seller discount ceiling. Deterministic, " +
      "ratcheted, fail closed.",
    baseUrl: base,
    network: BSV_NETWORK,
    x402: { network: BSV_NETWORK },
    payTo: (env.PAY_TO ?? "").trim(),
    tools: [
      {
        name: "profile",
        method: "POST",
        path: "/profile",
        priceSats: price,
        paid: true,
        description: "Signed trust profile for a subject (wallet:<id>, account:<n>, key:<thumbprint>).",
        body: '{"subject":"account:1"}',
      },
      {
        name: "profile_free",
        method: "GET",
        path: "/v1/profile/:subject",
        priceSats: 0,
        paid: false,
        description: "Free rate-limited profile read (200/day/IP).",
      },
      {
        name: "key",
        method: "GET",
        path: "/v1/key",
        priceSats: 0,
        paid: false,
        description: "Public ES256 key for offline verification.",
      },
      {
        name: "health",
        method: "GET",
        path: "/health",
        priceSats: 0,
        paid: false,
        description: "Free liveness probe.",
      },
    ],
  };
}

// ---------- MCP ----------

async function handleMcp(req: Request, env: Env): Promise<Response> {
  const base = publicBase(env);
  if (req.method !== "POST") {
    return json({
      server: SERVER_INFO,
      transport: "streamable-http",
      endpoint: `${base}/mcp`,
      tools: ["trust_profile", "trust_terms", "trust_verify", "trust_bind", "trust_leaderboard", "billing", "status"],
      docs: `${base}/docs`,
      hint: "POST JSON-RPC 2.0 here (initialize, tools/list, tools/call).",
    });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }, 400);
  }

  const ip = req.headers.get("cf-connecting-ip") ?? "0.0.0.0";
  const perMinute = num(env.RATE_LIMIT_PER_MIN, 60);
  const minute = new Date().toISOString().slice(0, 16);
  if (!(await allowRate(env, `trust:mcp:min:${ip}:${minute}`, perMinute))) {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: `rate limited: ${perMinute} requests/minute` } }, 429, {
      "retry-after": "60",
    });
  }

  const store = storeFor(env);
  let account: ToolContext["account"];
  let unlimited = false;
  try {
    ({ account, unlimited } = await accountFor(req, env, store));
  } catch (e) {
    const status = (e as { status?: number }).status ?? 401;
    return json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: e instanceof Error ? e.message : "unauthorized" } }, status);
  }

  const ctx: ToolContext = {
    store,
    account,
    now: Date.now,
    freeDaily: freeDaily(env),
    unlimited,
    profile: (subject) => profileFor(env, store, subject),
    verify: async ({ profile, signature }) => {
      const key = await trustPublicKey(env);
      if (!key) return { valid: false, expired: false };
      const valid = await verifyProfile(key.publicJwk, profile, signature);
      const expired = typeof profile.expiresAt === "string" && Date.parse(profile.expiresAt) <= Date.now();
      return { valid, expired };
    },
    bind: (args) => doBind(env, store, args, { internal: unlimited }),
    leaderboard: (limit) => store.listStates(limit),
    createCheckout: (planId) => {
      const plan = planById(planId);
      if (!plan) return Promise.resolve({ error: `unknown plan: ${planId}` });
      return createCheckoutSession(env, { accountId: account.id, plan });
    },
  };

  if (Array.isArray(body)) {
    const responses = [];
    for (const msg of body) {
      const r = await handleMessage(msg, ctx);
      if (r) responses.push(r);
    }
    return responses.length ? json(responses) : new Response(null, { status: 202, headers: CORS });
  }
  const response = await handleMessage(body, ctx);
  return response ? json(response) : new Response(null, { status: 202, headers: CORS });
}

// ---------- app ----------

// `strict: false` keeps trailing-slash variants working (/trust/docs/, /trust/mcp/, …).
const app = new Hono<{ Bindings: Env }>({ strict: false });

app.get("/", (c) => html(renderLanding(publicBase(c.env))));

app.get("/docs", (c) => html(renderDocs(publicBase(c.env))));

app.get("/health", (c) =>
  json({
    ok: true,
    service: "entangleit-trust",
    version: "0.1.0",
    signing_configured: Boolean(c.env.TRUST_KEY_JWK),
    billing_configured: stripeConfigured(c.env),
    price_sats: num(c.env.PRICE_SATS, 5),
    free_daily: freeDaily(c.env),
    ratchet_days: num(c.env.RATCHET_DAYS, RATCHET_DAYS_DEFAULT),
    pay_to: (c.env.PAY_TO ?? "").trim(),
    network: BSV_NETWORK,
    endpoints: {
      profile: `${publicBase(c.env)}/v1/profile/:subject`,
      paid_profile: `${publicBase(c.env)}/profile`,
      key: `${publicBase(c.env)}/v1/key`,
      mcp: `${publicBase(c.env)}/mcp`,
      manifest: `${publicBase(c.env)}/manifest`,
      docs: `${publicBase(c.env)}/docs`,
    },
  }),
);

app.get("/manifest", (c) => json(manifest(c.env)));

app.get("/v1/key", async (c) => {
  const key = await trustPublicKey(c.env);
  if (!key) return json({ error: { code: "signing_not_configured", message: "TRUST_KEY_JWK is not configured" } }, 503);
  return json({
    issuer: "trust.entangleit.com",
    alg: key.alg,
    keyId: key.keyId,
    publicJwk: key.publicJwk,
    note: "Verify ECDSA P-256 / SHA-256 (raw P1363, base64url) over the canonical JSON (sorted keys) of `profile`.",
  });
});

app.post("/v1/verify", async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as { profile?: TrustProfile; signature?: unknown };
  if (!body.profile || typeof body.signature !== "string") {
    return json({ error: { code: "invalid_request", message: "profile and signature are required" } }, 400);
  }
  const key = await trustPublicKey(c.env);
  if (!key) return json({ error: { code: "signing_not_configured", message: "TRUST_KEY_JWK is not configured" } }, 503);
  const valid = await verifyProfile(key.publicJwk, body.profile, body.signature);
  const expiresAt = typeof body.profile.expiresAt === "string" ? Date.parse(body.profile.expiresAt) : NaN;
  return json({
    valid,
    expired: Number.isFinite(expiresAt) ? expiresAt <= Date.now() : false,
    keyId: key.keyId,
  });
});

app.get("/v1/profile/:subject", async (c) => {
  const env = c.env;
  const subject = subjectFrom(c.req.param("subject"));
  if (!subject) return json({ error: { code: "invalid_subject", message: "invalid subject" } }, 400);
  const store = storeFor(env);
  if (!isInternal(c.req.raw, env)) {
    const ip = c.req.header("cf-connecting-ip") ?? "0.0.0.0";
    const day = new Date().toISOString().slice(0, 10);
    if (!(await allowDaily(env, `trust:profile:ip:${ip}:${day}`, 200))) {
      return json({ error: { code: "rate_limited", message: "200 free profile reads/day/IP; use MCP or x402 for more" } }, 429, {
        "retry-after": "3600",
      });
    }
  }
  const signed = await profileFor(env, store, subject);
  if (!signed) return json({ error: { code: "signing_not_configured", message: "TRUST_KEY_JWK is not configured" } }, 503);
  return json(signed);
});

app.post("/profile", handlePaidProfile);

app.get("/p/:subject", async (c) => {
  const env = c.env;
  const subject = subjectFrom(c.req.param("subject"));
  if (!subject) return html("<p>invalid subject</p>");
  const signed = await profileFor(env, storeFor(env), subject);
  if (!signed) return html("<p>Trust signing is not configured.</p>");
  return html(profilePage(publicBase(env), subject, signed.profile, signed.signature));
});

app.get("/badge/:subject", async (c) => {
  const env = c.env;
  const raw = c.req.param("subject").replace(/\.svg$/, "");
  const subject = subjectFrom(raw);
  if (!subject) {
    return new Response(badgeSvg("new", 0), { headers: { ...CORS, "content-type": "image/svg+xml", "cache-control": "public, max-age=60" } });
  }
  const signed = await profileFor(env, storeFor(env), subject);
  if (!signed) {
    return new Response(badgeSvg("new", 0), { headers: { ...CORS, "content-type": "image/svg+xml" } });
  }
  return new Response(badgeSvg(signed.profile.level, signed.profile.score), {
    headers: { ...CORS, "content-type": "image/svg+xml", "cache-control": "public, max-age=300" },
  });
});

app.get("/v1/bind/challenge", async (c) => {
  const nonce = crypto.randomUUID();
  if (c.env.METER) await c.env.METER.put(`trust:bind:${nonce}`, "1", { expirationTtl: 600 });
  return json({
    nonce,
    message: `bind:<key>:<other>:${nonce}`,
    note: "Sign `bind:<your key subject>:<other subject>:<nonce>` with your P-256 key (ES256, base64url), then POST /v1/bind.",
  });
});

app.post("/v1/bind", async (c) => {
  const env = c.env;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const result = await doBind(env, storeFor(env), body, { internal: isInternal(c.req.raw, env) });
  return json(result, result.ok ? 200 : 400);
});

app.post("/v1/ingest", async (c) => {
  const env = c.env;
  if (!isInternal(c.req.raw, env)) {
    return json({ error: { code: "unauthorized", message: "x-trust-internal header required" } }, 401);
  }
  let body: Record<string, unknown>;
  try {
    body = (await c.req.json()) as Record<string, unknown>;
  } catch {
    return json({ error: { code: "invalid_json" } }, 400);
  }
  const store = storeFor(env);
  const now = Date.now();
  let observations = 0;
  let attestations = 0;
  let reputations = 0;
  const errors: string[] = [];

  const list = Array.isArray(body.observations) ? body.observations : [];
  for (const item of list.slice(0, 100)) {
    const o = item as Partial<ObservationInput>;
    if (
      !o ||
      typeof o.subject !== "string" ||
      typeof o.source !== "string" ||
      typeof o.kind !== "string" ||
      typeof o.ref !== "string"
    ) {
      errors.push("skipped malformed observation");
      continue;
    }
    if (!SUBJECT_RE.test(o.subject)) {
      errors.push(`skipped invalid subject: ${o.subject}`);
      continue;
    }
    const stored = await ingestObservation(
      store,
      { subject: o.subject, source: o.source, kind: o.kind, ref: o.ref, value: o.value ?? null, meta: o.meta, observed_at: o.observed_at ?? now },
      now,
    );
    if (stored) observations += 1;
  }

  if (body.attestation) {
    const signature = typeof body.signature === "string" ? body.signature : "";
    if (!isAttestationLike(body.attestation) || !signature) {
      errors.push("attestation and signature are required together");
    } else {
      const key = await agentpayKey(env);
      if (!key) errors.push("agentpay attestation key unavailable");
      else if (!(await verifySignedObject(key.publicJwk, body.attestation, signature))) errors.push("bad attestation signature");
      else {
        const att = body.attestation;
        const stored = await ingestObservation(store, attestationObservation(att), now);
        if (stored) attestations += 1;
      }
    }
  }

  const reputation = body.reputation as { account?: unknown; reputation?: unknown; stats?: unknown } | undefined;
  if (reputation) {
    const account = Number(reputation.account);
    const rep = reputation.reputation as Record<string, unknown> | undefined;
    if (!Number.isFinite(account) || account <= 0 || !rep || typeof rep.score !== "number") {
      errors.push("reputation requires {account, reputation.score}");
    } else {
      const day = new Date(now).toISOString().slice(0, 10);
      const stored = await ingestObservation(
        store,
        {
          subject: `account:${account}`,
          source: "bounties",
          kind: "reputation",
          ref: `${account}:${day}`,
          value: rep.score,
          meta: { reputation: rep, stats: reputation.stats ?? {} },
        },
        now,
      );
      if (stored) reputations += 1;
    }
  }

  return json({ ok: true, observations, attestations, reputations, errors });
});

app.post("/v1/reconcile", async (c) => {
  const env = c.env;
  if (!isInternal(c.req.raw, env)) {
    return json({ error: { code: "unauthorized", message: "x-trust-internal header required" } }, 401);
  }
  const body = (await c.req.json().catch(() => ({}))) as { limit?: unknown };
  const limit = Number.isFinite(Number(body.limit)) ? Number(body.limit) : num(env.RECONCILE_LIMIT, 200);
  const result = await reconcile(storeFor(env), env, { limit });
  return json(result);
});

app.all("/mcp", (c) => handleMcp(c.req.raw, c.env));

app.get("/v1/status", async (c) => {
  const stats = await storeFor(c.env).stats();
  return json({
    service: "entangleit-trust",
    version: "0.1.0",
    stats,
    signing_configured: Boolean(c.env.TRUST_KEY_JWK),
    billing_configured: stripeConfigured(c.env),
    free_daily: freeDaily(c.env),
    ratchet_days: num(c.env.RATCHET_DAYS, RATCHET_DAYS_DEFAULT),
  });
});

app.get("/v1/plans", (c) =>
  json({
    billing_configured: stripeConfigured(c.env),
    plans: PLANS.map((p) => ({
      id: p.id,
      label: p.label,
      description: p.description,
      amount_cents: p.amountCents,
      credits: p.credits,
      mode: p.mode,
    })),
  }),
);

app.get("/v1/billing/plans", (c) =>
  json({
    billing_configured: stripeConfigured(c.env),
    plans: PLANS.map((p) => ({
      id: p.id,
      label: p.label,
      description: p.description,
      amount_cents: p.amountCents,
      credits: p.credits,
      mode: p.mode,
    })),
  }),
);

app.post("/v1/billing/checkout", async (c) => {
  const store = storeFor(c.env);
  let account: ToolContext["account"];
  try {
    ({ account } = await accountFor(c.req.raw, c.env, store));
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : "unauthorized" }, (e as { status?: number }).status ?? 401);
  }
  let body: Record<string, unknown> = {};
  try {
    body = (await c.req.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const plan = planById(String(body.plan ?? ""));
  if (!plan) return json({ error: "unknown plan", plans: PLANS.map((p) => p.id) }, 400);
  const res = await createCheckoutSession(c.env, { accountId: account.id, plan });
  if ("error" in res) return json({ error: res.error }, 503);
  return json({ url: res.url, plan: plan.id, credits: plan.credits });
});

app.post("/v1/billing/webhook", async (c) => {
  if (!c.env.STRIPE_WEBHOOK_SECRET) return json({ error: "billing not configured" }, 503);
  const payload = await c.req.text();
  const signature = c.req.header("stripe-signature") ?? "";
  if (!(await verifyWebhookSignature(c.env.STRIPE_WEBHOOK_SECRET, payload, signature))) {
    return json({ error: "invalid signature" }, 400);
  }
  const note = await handleStripeEvent(c.env, storeFor(c.env), parseEvent(payload));
  return json({ received: true, handled: note });
});

app.get("/thanks", (c) =>
  html(
    `<!doctype html><html><head><meta charset="utf-8"><title>EntangleIT Trust — thank you</title>` +
      `<style>body{background:#0b0e13;color:#e8ecf2;font:16px/1.6 system-ui;display:grid;place-items:center;height:100vh;margin:0}` +
      `main{max-width:34rem;text-align:center}a{color:#2dd4bf}</style></head><body><main>` +
      `<h1>Payment received</h1><p>Credits are applied to your Trust account automatically. ` +
      `Go back to your agent and ask it for terms.</p><p><a href="${publicBase(c.env)}/">EntangleIT Trust</a></p></main></body></html>`,
  ),
);

app.notFound((c) => json({ error: "not found", mount: "/trust" }, 404));

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    const redirect = mountRedirect(url.pathname);
    if (redirect && (req.method === "GET" || req.method === "HEAD")) {
      return Response.redirect(`${url.origin}${redirect}`, 308);
    }

    const path = routePath(url.pathname);
    if (path !== url.pathname) {
      const rewritten = new URL(req.url);
      rewritten.pathname = path;
      req = new Request(rewritten.toString(), req);
    }
    return app.fetch(req, env);
  },
};