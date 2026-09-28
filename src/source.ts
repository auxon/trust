/**
 * Signal sources: pull verified history out of the rails without touching
 * their code.
 *
 * agentpay's tables live in the same `entangleit` D1, so spend snapshots are
 * read straight from the ledger (read-only, aggregate-only). BSVBounties
 * reputation is fetched from its public API. Attestations and webhook pushes
 * are the signed upgrade path; reconcile is the zero-integration floor.
 */
import type { SpendMetrics } from "./core.ts";
import { ingestObservation } from "./ingest.ts";
import type { D1Like, TrustStore } from "./store.ts";

export interface SourceEnv {
  DB?: D1Like;
  BOUNTIES?: { fetch(input: Request): Promise<Response> };
  AGENTPAY?: { fetch(input: Request): Promise<Response> };
  BOUNTIES_API_URL?: string;
  AGENTPAY_PUBLIC_URL?: string;
}

export interface ReconcileResult {
  wallets: number;
  accounts: number;
  bindings: number;
  spendSnapshots: number;
  reputations: number;
  errors: string[];
}

export function dayKey(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

function toIso(value: unknown): string | null {
  if (typeof value !== "string" || !value) return null;
  const parsed = Date.parse(value.includes("T") ? value : `${value.replace(" ", "T")}Z`);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

const base = (value: string | undefined, fallback: string): string => (value ?? fallback).replace(/\/$/, "");

/** Public reputation for a numbered account. Binding first, URL fallback. */
export async function fetchBountiesAccount(env: SourceEnv, number: number): Promise<Record<string, unknown> | null> {
  const path = `/v1/accounts/${number}`;
  try {
    let res: Response;
    if (env.BOUNTIES) {
      res = await env.BOUNTIES.fetch(new Request(`https://bsv-bounties.internal${path}`));
    } else {
      res = await fetch(`${base(env.BOUNTIES_API_URL, "https://bsv-bounties.richard-hein.workers.dev")}${path}`);
    }
    if (!res.ok) return null;
    const body = (await res.json()) as Record<string, unknown>;
    return body && typeof body === "object" ? body : null;
  } catch {
    return null;
  }
}

/** agentpay's public attestation key (cached by the caller's key cache). */
export async function fetchAgentpayPublicKey(
  env: SourceEnv,
): Promise<{ publicJwk: JsonWebKey; keyId: string } | null> {
  try {
    let res: Response;
    if (env.AGENTPAY) {
      res = await env.AGENTPAY.fetch(new Request("https://agentpay-api.internal/attestations/key"));
    } else {
      res = await fetch(`${base(env.AGENTPAY_PUBLIC_URL, "https://entangleit.com/api/agentpay")}/attestations/key`);
    }
    if (!res.ok) return null;
    const body = (await res.json()) as { publicJwk?: JsonWebKey; keyId?: string };
    if (!body.publicJwk || typeof body.keyId !== "string") return null;
    return { publicJwk: body.publicJwk, keyId: body.keyId };
  } catch {
    return null;
  }
}

interface WalletAgg {
  n: number;
  services: number;
  cents: number;
  first_at: string | null;
  last_at: string | null;
  refunds?: number;
  payees?: number;
  payouts?: number;
  earned?: number;
}

async function aggRows(db: D1Like, sql: string, limit: number): Promise<Record<string, unknown>[]> {
  const res = await db.prepare(sql).bind(limit).all<Record<string, unknown>>();
  return res.results ?? [];
}

function buildSpend(agg: WalletAgg): SpendMetrics {
  return {
    settledPayments: Number(agg.n ?? 0),
    distinctServices: Number(agg.services ?? 0),
    ...(typeof agg.payees === "number" ? { distinctPayTo: agg.payees } : {}),
    spentCents: Number(agg.cents ?? 0),
    refundedCents: Number(agg.refunds ?? 0),
    bountyPayouts: Number(agg.payouts ?? 0),
    earnedCents: Number(agg.earned ?? 0),
    firstPaymentAt: toIso(agg.first_at),
    lastPaymentAt: toIso(agg.last_at),
  };
}

/**
 * Pull spend snapshots, bindings, and reputations. Idempotent per day:
 * re-running moves nothing. Never writes to any table but tr_*.
 */
export async function reconcile(
  store: TrustStore,
  env: SourceEnv,
  opts: { limit?: number; now?: number } = {},
): Promise<ReconcileResult> {
  const now = opts.now ?? Date.now();
  const limit = Math.max(1, Math.min(1000, opts.limit ?? 200));
  const result: ReconcileResult = {
    wallets: 0,
    accounts: 0,
    bindings: 0,
    spendSnapshots: 0,
    reputations: 0,
    errors: [],
  };
  if (!env.DB) {
    result.errors.push("no DB bound (local memory mode)");
    return result;
  }

  // 1. Spend aggregates per wallet (receipts are settled payments).
  const aggregates = await aggRows(
    env.DB,
    `SELECT wallet_id, COUNT(*) AS n, COUNT(DISTINCT NULLIF(service, '')) AS services,
            COALESCE(SUM(amount_cents), 0) AS cents, MIN(created_at) AS first_at, MAX(created_at) AS last_at
     FROM ap_receipts GROUP BY wallet_id ORDER BY n DESC LIMIT ?`,
    limit,
  ).catch(() => [] as Record<string, unknown>[]);
  // Refunds are money back from a spend attempt, not spend: a failed bounty
  // funding does not contaminate a wallet for life. Only UNMATCHED refunds
  // (positive refunds with no debit spend) are a red flag — money appearing
  // from nowhere. The gate sees net unmatched refunds, never below zero.
  const refunds = await aggRows(
    env.DB,
    `SELECT wallet_id, MAX(0, COALESCE(SUM(refunded), 0) + COALESCE(SUM(debited), 0)) AS refunds
     FROM (
       SELECT wallet_id, amount_cents AS refunded, 0 AS debited FROM ap_ledger
       WHERE kind = 'refund' AND amount_cents > 0
       UNION ALL
       SELECT wallet_id, 0 AS refunded, amount_cents AS debited FROM ap_ledger
       WHERE kind = 'debit' AND amount_cents < 0
     ) GROUP BY wallet_id LIMIT ?`,
    limit,
  ).catch(() => [] as Record<string, unknown>[]);
  const payees = await aggRows(
    env.DB,
    `SELECT wallet_id, COUNT(DISTINCT json_extract(meta_json, '$.payTo')) AS payees FROM ap_ledger
     WHERE kind = 'debit' AND json_extract(meta_json, '$.payTo') IS NOT NULL GROUP BY wallet_id LIMIT ?`,
    limit,
  ).catch(() => [] as Record<string, unknown>[]);
  const payouts = await aggRows(
    env.DB,
    `SELECT wallet_id, COUNT(*) AS payouts, COALESCE(SUM(amount_cents), 0) AS earned FROM ap_ledger
     WHERE kind = 'adjust' AND json_extract(meta_json, '$.type') = 'bounty_payout' GROUP BY wallet_id LIMIT ?`,
    limit,
  ).catch(() => [] as Record<string, unknown>[]);

  const byWallet = new Map<string, WalletAgg>();
  for (const row of aggregates) {
    const wallet = String(row.wallet_id);
    byWallet.set(wallet, {
      n: Number(row.n ?? 0),
      services: Number(row.services ?? 0),
      cents: Number(row.cents ?? 0),
      first_at: row.first_at == null ? null : String(row.first_at),
      last_at: row.last_at == null ? null : String(row.last_at),
    });
  }
  const merge = (rows: Record<string, unknown>[], field: string): void => {
    for (const row of rows) {
      const wallet = String(row.wallet_id);
      const agg = byWallet.get(wallet);
      if (agg) (agg as unknown as Record<string, number>)[field] = Number(row[field] ?? 0);
    }
  };
  merge(refunds, "refunds");
  merge(payees, "payees");
  merge(payouts, "payouts");
  merge(payouts, "earned");

  const day = dayKey(now);
  for (const [wallet, agg] of byWallet) {
    const stored = await ingestObservation(
      store,
      {
        subject: `wallet:${wallet}`,
        source: "agentpay-d1",
        kind: "spend_snapshot",
        ref: `${wallet}:${day}`,
        value: agg.cents,
        meta: { metrics: buildSpend(agg) },
      },
      now,
    );
    if (stored) result.spendSnapshots += 1;
  }
  result.wallets = byWallet.size;

  // 2. Wallet <-> bounty account links recorded by agentpay's bounty bridge.
  const links = await aggRows(
    env.DB,
    `SELECT DISTINCT wallet_id, worker_account FROM ap_bounty_links
     WHERE worker_account IS NOT NULL LIMIT ?`,
    limit,
  ).catch(() => [] as Record<string, unknown>[]);
  const accountNumbers = new Set<number>();
  for (const row of links) {
    const wallet = String(row.wallet_id);
    const account = Number(row.worker_account);
    if (!Number.isFinite(account) || account <= 0) continue;
    accountNumbers.add(account);
    const ok = await store.addBinding({
      a: `wallet:${wallet}`,
      b: `account:${account}`,
      proof: "agentpay:bounty_link",
      evidence: "ap_bounty_links",
      bound_at: now,
    });
    await store.touchSubject(`wallet:${wallet}`, now);
    await store.touchSubject(`account:${account}`, now);
    if (ok) result.bindings += 1;
  }
  result.accounts = accountNumbers.size;

  // 3. Reputation snapshots for every known account.
  for (const account of accountNumbers) {
    const body = await fetchBountiesAccount(env, account);
    if (!body) {
      result.errors.push(`account ${account}: reputation unavailable`);
      continue;
    }
    const reputation = (body.reputation ?? body) as Record<string, unknown>;
    if (typeof reputation.score !== "number") {
      result.errors.push(`account ${account}: malformed reputation`);
      continue;
    }
    const stats = (body.stats ?? {}) as Record<string, unknown>;
    const stored = await ingestObservation(
      store,
      {
        subject: `account:${account}`,
        source: "bounties",
        kind: "reputation",
        ref: `${account}:${day}`,
        value: reputation.score,
        meta: { reputation, stats },
      },
      now,
    );
    if (stored) result.reputations += 1;
  }

  return result;
}