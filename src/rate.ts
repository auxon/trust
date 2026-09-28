/**
 * KV-backed rate limits. KV is not atomic, so counters are approximate —
 * they exist to bound abuse, not to be exact.
 */
import type { ReplayKV } from "./x402.ts";

export interface RateEnv {
  METER?: ReplayKV;
}

/** Sliding-minute request cap. Fails open when KV is not bound. */
export async function allowRate(env: RateEnv, key: string, limit: number, ttlSeconds = 120): Promise<boolean> {
  const kv = env.METER;
  if (!kv) return true;
  const current = Number(await kv.get(key)) || 0;
  if (current >= limit) return false;
  await kv.put(key, String(current + 1), { expirationTtl: ttlSeconds });
  return true;
}

/** Daily counter cap (per IP). Fails open when KV is not bound. */
export async function allowDaily(env: RateEnv, key: string, limit: number): Promise<boolean> {
  const kv = env.METER;
  if (!kv) return true;
  const current = Number(await kv.get(key)) || 0;
  if (current >= limit) return false;
  await kv.put(key, String(current + 1), { expirationTtl: 2 * 24 * 3600 });
  return true;
}