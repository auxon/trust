/**
 * Signal ingestion: verified facts in, axes out.
 *
 * Everything here is deterministic and fail-closed: a malformed snapshot is
 * treated as absent, never guessed. Observations are idempotent on
 * (source, ref), so retried webhooks and reconcile runs move nothing twice.
 */
import { fromBase64Url, spendVerified, stableStringify, type MarketMetrics, type SpendMetrics, type WorkMetrics } from "./core.ts";
import type { BindingRow, Observation, ObservationInput, TrustStore } from "./store.ts";

// ---------- bindings ----------

/** Undirected closure over active bindings: every subject merged with `subject`. */
export function resolveMembers(bindings: BindingRow[], subject: string): string[] {
  const adjacency = new Map<string, Set<string>>();
  for (const b of bindings) {
    if (b.revoked_at !== null) continue;
    if (!adjacency.has(b.a)) adjacency.set(b.a, new Set());
    if (!adjacency.has(b.b)) adjacency.set(b.b, new Set());
    adjacency.get(b.a)!.add(b.b);
    adjacency.get(b.b)!.add(b.a);
  }
  const seen = new Set<string>([subject]);
  const queue = [subject];
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const next of adjacency.get(current) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return [...seen].sort();
}

// ---------- attestation verification ----------

export interface AttestationMetricsLike {
  settledPayments: number;
  distinctServices: number;
  distinctPayTo?: number;
  spentCents: number;
  refundedCents: number;
  bountyPayouts?: number;
  earnedCents?: number;
  firstPaymentAt?: string | null;
  lastPaymentAt?: string | null;
}

export interface AttestationLike {
  v: number;
  iss: string;
  wallet?: string;
  sub?: string;
  windowDays?: number;
  issuedAt: string;
  expiresAt: string;
  metrics: AttestationMetricsLike;
}

/** Verify any canonical-JSON object signed by an ES256 issuer key. */
export async function verifySignedObject(
  publicJwk: JsonWebKey,
  object: unknown,
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
      new TextEncoder().encode(stableStringify(object)),
    );
  } catch {
    return false;
  }
}

export function isAttestationLike(value: unknown): value is AttestationLike {
  if (!value || typeof value !== "object") return false;
  const a = value as Partial<AttestationLike>;
  if (typeof a.wallet !== "string" && typeof a.sub !== "string") return false;
  if (typeof a.issuedAt !== "string") return false;
  const m = a.metrics as Partial<AttestationMetricsLike> | undefined;
  if (!m || typeof m !== "object") return false;
  return (
    typeof m.settledPayments === "number" &&
    typeof m.distinctServices === "number" &&
    typeof m.spentCents === "number" &&
    typeof m.refundedCents === "number"
  );
}

/** Observation for a verified attestation, keyed to the wallet. */
export function attestationObservation(attestation: AttestationLike): ObservationInput {
  const wallet = attestation.wallet ?? attestation.sub ?? "unknown";
  return {
    subject: `wallet:${wallet}`,
    source: "agentpay",
    kind: "attestation",
    ref: `${wallet}:${attestation.issuedAt}`,
    value: attestation.metrics.spentCents,
    meta: {
      metrics: attestation.metrics,
      sub: attestation.sub ?? null,
      expiresAt: attestation.expiresAt,
    },
  };
}

// ---------- axis extraction ----------

export function parseMeta(observation: Observation): Record<string, unknown> {
  try {
    const parsed = JSON.parse(observation.meta_json) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function validSpendMetrics(value: unknown): SpendMetrics | null {
  if (!value || typeof value !== "object") return null;
  const m = value as Partial<SpendMetrics>;
  if (
    typeof m.settledPayments !== "number" ||
    typeof m.distinctServices !== "number" ||
    typeof m.spentCents !== "number" ||
    typeof m.refundedCents !== "number"
  ) {
    return null;
  }
  return {
    settledPayments: m.settledPayments,
    distinctServices: m.distinctServices,
    ...(typeof m.distinctPayTo === "number" ? { distinctPayTo: m.distinctPayTo } : {}),
    spentCents: m.spentCents,
    refundedCents: m.refundedCents,
    ...(typeof m.bountyPayouts === "number" ? { bountyPayouts: m.bountyPayouts } : {}),
    ...(typeof m.earnedCents === "number" ? { earnedCents: m.earnedCents } : {}),
    ...(typeof m.firstPaymentAt === "string" || m.firstPaymentAt === null ? { firstPaymentAt: m.firstPaymentAt } : {}),
    ...(typeof m.lastPaymentAt === "string" || m.lastPaymentAt === null ? { lastPaymentAt: m.lastPaymentAt } : {}),
  };
}

/** Latest verified spend snapshot across the subject set (attestation or reconcile pull). */
export function spendFromObservations(observations: Observation[]): SpendMetrics | null {
  for (const o of observations) {
    if (o.kind !== "attestation" && o.kind !== "spend_snapshot") continue;
    const metrics = validSpendMetrics(parseMeta(o).metrics ?? parseMeta(o));
    if (metrics) return metrics;
  }
  return null;
}

export function workFromObservations(observations: Observation[]): WorkMetrics | null {
  let completed = 0;
  const paidRefs = new Set<string>();
  for (const o of observations) {
    if (o.kind === "bounty_paid" && !paidRefs.has(o.ref)) {
      paidRefs.add(o.ref);
      completed += 1;
    }
  }
  for (const o of observations) {
    if (o.kind !== "reputation") continue;
    const meta = parseMeta(o);
    const raw = (meta.reputation ?? meta) as Record<string, unknown>;
    if (typeof raw.score !== "number") continue;
    const stats = meta.stats as Record<string, unknown> | undefined;
    const statsCompleted = typeof stats?.bountiesCompleted === "number" ? stats.bountiesCompleted : 0;
    return {
      score: raw.score,
      provisional: Boolean(raw.provisional),
      slashes: Number(raw.slashes ?? 0),
      completed: Math.max(completed, statsCompleted),
      verifyPassRate: typeof raw.verifyPassRate === "number" ? raw.verifyPassRate : null,
      ...(typeof raw.tier === "string" ? { tier: raw.tier } : {}),
      ...(typeof raw.verified === "boolean" ? { verified: raw.verified } : {}),
    };
  }
  return null;
}

export function marketFromObservations(observations: Observation[]): MarketMetrics {
  const services = new Set<string>();
  let calls = 0;
  let disputesLost = 0;
  for (const o of observations) {
    if (o.kind === "payment_settled" || o.kind === "gateway_call") {
      calls += 1;
      const service = parseMeta(o).service;
      if (typeof service === "string" && service) services.add(service);
    }
    if (o.kind === "dispute_lost") disputesLost += 1;
  }
  return { services: services.size, calls, disputesLost };
}

// ---------- ingestion ----------

export async function ingestObservation(store: TrustStore, input: ObservationInput, now = Date.now()): Promise<boolean> {
  await store.touchSubject(input.subject, input.observed_at ?? now);
  return store.addObservation({ ...input, observed_at: input.observed_at ?? now });
}

/** True when the latest spend snapshot would qualify for the spend axis. */
export function spendEligible(observations: Observation[], now = Date.now()): boolean {
  return spendVerified(spendFromObservations(observations), now).eligible;
}