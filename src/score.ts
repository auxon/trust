/**
 * Trust scoring: verified axes -> level -> terms. Pure and deterministic.
 *
 * The rules, in one breath: a level needs verified spend AND verified work;
 * stronger levels need volume, distinct counterparties, time, and a clean
 * pass rate; trust climbs at most one level per ratchet window and drops
 * immediately when evidence drops. Jev never decides a level — an advisory
 * "hold" can only step the terms down one level.
 */
import {
  LEVELS,
  LEVEL_THRESHOLDS,
  TRUST_ISSUER,
  TRUST_VERSION,
  levelAt,
  levelIndex,
  spendVerified,
  termsFor,
  workVerified,
  type MarketMetrics,
  type SpendMetrics,
  type TrustBand,
  type TrustLevel,
  type TrustProfile,
  type WorkMetrics,
} from "./core.ts";

export const PROFILE_TTL_MS_DEFAULT = 86_400_000;
export const RATCHET_DAYS_DEFAULT = 7;

export interface ComputeProfileInput {
  subject: string;
  members: string[];
  spend: SpendMetrics | null;
  work: WorkMetrics | null;
  market: MarketMetrics | null;
  now: number;
  storedLevel?: TrustLevel;
  /** When the last level upgrade happened (from tr_state.updated_at). */
  lastUpgradeAt?: number;
  ratchetDays?: number;
  ttlMs?: number;
  band?: TrustBand | null;
}

function ageDays(spend: SpendMetrics | null, now: number): number {
  if (!spend?.firstPaymentAt) return 0;
  const first = Date.parse(spend.firstPaymentAt);
  if (!Number.isFinite(first)) return 0;
  return (now - first) / 86_400_000;
}

function meetsThresholds(
  tier: "trusted" | "elite",
  spend: SpendMetrics,
  work: WorkMetrics,
  now: number,
): boolean {
  const t = LEVEL_THRESHOLDS[tier];
  const payees = spend.distinctPayTo ?? spend.distinctServices ?? 0;
  if (spend.settledPayments < t.payments) return false;
  if (payees < t.payees) return false;
  if ((spend.spentCents ?? 0) < t.spentCents) return false;
  if ((work.completed ?? 0) < t.completed) return false;
  if (typeof work.verifyPassRate !== "number" || work.verifyPassRate < t.passRate) return false;
  if (ageDays(spend, now) < t.ageDays) return false;
  return true;
}

function computedLevel(spend: SpendMetrics | null, work: WorkMetrics | null, now: number): { level: TrustLevel; reasons: string[] } {
  const reasons: string[] = [];
  const s = spendVerified(spend, now);
  const w = workVerified(work);
  if (s.eligible) reasons.push("spend_verified");
  else reasons.push(`spend:${s.reason}`);
  if (w.eligible) reasons.push("work_verified");
  else reasons.push(`work:${w.reason}`);

  if (!s.eligible || !w.eligible) {
    if (s.eligible || w.eligible) return { level: "building", reasons };
    return { level: "new", reasons };
  }
  if (spend && work && meetsThresholds("elite", spend, work, now)) {
    reasons.push("thresholds:elite");
    return { level: "elite", reasons };
  }
  if (spend && work && meetsThresholds("trusted", spend, work, now)) {
    reasons.push("thresholds:trusted");
    return { level: "trusted", reasons };
  }
  return { level: "proven", reasons };
}

/**
 * Climb at most one step per window; any drop applies immediately.
 * A subject seen for the first time lands at its computed level — the
 * evidence itself is slow to fake (age, distinct counterparties), and the
 * ratchet then constrains everything we observe from here on.
 */
export function ratchetLevel(
  computed: TrustLevel,
  stored: TrustLevel | undefined,
  lastUpgradeAt: number | undefined,
  now: number,
  ratchetDays = RATCHET_DAYS_DEFAULT,
): TrustLevel {
  if (!stored) return computed;
  const ci = levelIndex(computed);
  const pi = levelIndex(stored);
  if (ci <= pi) return computed;
  const windowMs = Math.max(0, ratchetDays) * 86_400_000;
  const since = lastUpgradeAt ? now - lastUpgradeAt : Number.POSITIVE_INFINITY;
  if (since < windowMs) return stored;
  return levelAt(Math.min(ci, pi + 1));
}

export function scoreFor(spend: SpendMetrics | null, work: WorkMetrics | null, now: number): number {
  let score = 0;
  const s = spendVerified(spend, now);
  const w = workVerified(work);
  if (s.eligible && spend) {
    score += 300 + Math.min(150, Math.max(0, (spend.settledPayments - 10) * 2));
  } else if (spend && spend.settledPayments > 0) {
    score += Math.min(100, spend.settledPayments * 5);
  }
  if (w.eligible && work) {
    score += 400 + Math.min(100, Math.max(0, (work.score - 650) / 2));
  } else if (work && work.score > 0) {
    score += Math.min(200, Math.round(work.score / 5));
  }
  if (s.eligible && w.eligible) score += 100;
  if (work?.verified) score += 50;
  return Math.min(1000, Math.round(score));
}

export function confidenceFor(spend: SpendMetrics | null, work: WorkMetrics | null, now: number): number {
  const dataPoints = (spend?.settledPayments ?? 0) + (work?.completed ?? 0) * 5;
  let confidence = 0.2 + Math.min(0.5, dataPoints / 200);
  if (spendVerified(spend, now).eligible) confidence += 0.15;
  if (workVerified(work).eligible) confidence += 0.15;
  return Math.min(0.99, Number(confidence.toFixed(2)));
}

export function computeProfile(input: ComputeProfileInput): TrustProfile {
  const { subject, members, spend, work, market, now } = input;
  const { level: computed, reasons } = computedLevel(spend, work, now);
  const level = ratchetLevel(
    computed,
    input.storedLevel,
    input.lastUpgradeAt,
    now,
    input.ratchetDays ?? RATCHET_DAYS_DEFAULT,
  );

  const ttl = input.ttlMs ?? PROFILE_TTL_MS_DEFAULT;
  return {
    v: TRUST_VERSION,
    iss: TRUST_ISSUER,
    sub: subject,
    members: [...members].sort(),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttl).toISOString(),
    level,
    score: scoreFor(spend, work, now),
    confidence: confidenceFor(spend, work, now),
    axes: { spend, work, market },
    terms: termsFor(level, input.band ?? null),
    reasons,
    ...(input.band ? { band: input.band } : {}),
  };
}

export function levels(): TrustLevel[] {
  return [...LEVELS];
}