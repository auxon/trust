/**
 * Strict x402 v2 (exact × bsv:mainnet) seller helpers, shared with the other
 * EntangleIT connectors: no keys here — the worker verifies buyer-signed
 * transactions and broadcasts them via ARC.
 */
import { Transaction } from "@bsv/sdk";

export const X402_VERSION = 2;
export const BSV_SCHEME = "exact";
export const BSV_NETWORK = "bsv:mainnet";
export const BSV_ASSET = "native:BSV";
export const DEFAULT_ARC_URL = "https://arc.gorillapool.io/v1";

export interface BsvPaymentRequirements {
  x402Version: number;
  scheme: string;
  network: string;
  amount: string;
  payTo: string;
  asset: string;
  resource: { url: string; description: string; mimeType: string };
  extra: { satoshis: string; dustFloor: string; arcUrl: string };
}

export interface BsvPaymentPayload {
  x402Version: number;
  scheme: string;
  network: string;
  txHex: string;
  encoding: "raw-hex" | "beef-hex";
}

export interface X402Env {
  ARC_URL?: string;
  ARC_API_KEY?: string;
  METER?: ReplayKV;
}

const te = new TextEncoder();
const td = new TextDecoder();

export function b64encodeJson(obj: unknown): string {
  const bytes = te.encode(JSON.stringify(obj));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64decodeJson<T>(b64: string): T {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return JSON.parse(td.decode(bytes)) as T;
}

export function buildRequirements(args: {
  url: string;
  description: string;
  satoshis: number;
  payTo: string;
  arcUrl: string;
}): BsvPaymentRequirements {
  return {
    x402Version: X402_VERSION,
    scheme: BSV_SCHEME,
    network: BSV_NETWORK,
    amount: String(args.satoshis),
    payTo: args.payTo,
    asset: BSV_ASSET,
    resource: { url: args.url, description: args.description, mimeType: "application/json" },
    extra: { satoshis: String(args.satoshis), dustFloor: "1", arcUrl: args.arcUrl },
  };
}

export type VerifyResult =
  | { success: true; payer: string; txid: string; txHex: string; amount: number }
  | { success: false; errorReason: string };

const fail = (errorReason: string): VerifyResult => ({ success: false, errorReason });

/** Structural verify: envelope matches, tx pays payTo >= amount, sane totals. */
export async function verifyBsvPayment(
  requirements: BsvPaymentRequirements,
  payload: BsvPaymentPayload,
): Promise<VerifyResult> {
  if (requirements.x402Version !== X402_VERSION) return fail("invalid_x402_version");
  if (requirements.scheme !== BSV_SCHEME) return fail("invalid_scheme");
  if (requirements.network !== BSV_NETWORK) return fail("invalid_network");
  const want = Number.parseInt(requirements.amount, 10);
  if (!Number.isFinite(want) || want <= 0) return fail("invalid_payment_requirements");
  if (!requirements.payTo || requirements.payTo.length < 26) return fail("invalid_payment_requirements");
  if (payload.x402Version !== X402_VERSION || payload.scheme !== BSV_SCHEME || payload.network !== BSV_NETWORK) {
    return fail("invalid_payload");
  }
  if (!payload.txHex || payload.txHex.length < 100 || payload.txHex.length > 2_000_000) {
    return fail("invalid_payload");
  }

  let tx: Transaction;
  try {
    tx = Transaction.fromHex(payload.txHex);
  } catch {
    return fail("invalid_payload");
  }

  let paid = 0;
  let txid = "";
  try {
    txid = tx.id("hex");
    const { P2PKH } = await import("@bsv/sdk");
    const expected = new P2PKH().lock(requirements.payTo).toHex();
    for (const out of tx.outputs) {
      try {
        if (out.lockingScript.toHex() === expected) paid += out.satoshis ?? 0;
      } catch {
        continue;
      }
    }
  } catch {
    return fail("invalid_payload");
  }
  if (paid < want) return fail("invalid_exact_bsv_payment_recipient_mismatch");

  let outTotal = 0;
  for (const o of tx.outputs) outTotal += o.satoshis ?? 0;
  if (outTotal <= 0 || outTotal > 100_000_000) return fail("invalid_payload");

  let payer = "bsv:unknown";
  if (tx.inputs.length > 0) {
    const first = tx.inputs[0]!;
    const ref = first.sourceTXID ?? first.sourceTransaction?.id("hex") ?? "";
    if (ref) payer = `bsv:input:${ref.slice(0, 16)}`;
  }
  return { success: true, payer, txid, txHex: payload.txHex, amount: paid };
}

export async function arcBroadcast(env: X402Env, rawTxHex: string): Promise<{ txid: string }> {
  const base = (env.ARC_URL || DEFAULT_ARC_URL).replace(/\/$/, "");
  const apiKey = typeof env.ARC_API_KEY === "string" ? env.ARC_API_KEY : "";
  const res = await fetch(`${base}/tx`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(apiKey ? { Authorization: `Bearer ${apiKey}`, "X-API-Key": apiKey, api_key: apiKey } : {}),
      "XDeployment-ID": "entangleit-trust-v1",
    },
    body: JSON.stringify({ rawTx: rawTxHex }),
  });
  const text = await res.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    json = { raw: text.slice(0, 2000) };
  }
  if (!res.ok) {
    const err = new Error(`ARC rejected (${res.status}): ${text.slice(0, 400)}`) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }
  const txid = (json["txid"] as string) ?? (json["txId"] as string) ?? (json["hash"] as string) ?? "";
  return { txid };
}

export interface ReplayKV {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

/** One txid pays for exactly one call. Fails open when KV is not bound. */
export async function claimPaymentTxid(env: X402Env, txid: string): Promise<boolean> {
  const kv = env.METER;
  if (!kv) return true;
  const key = `trust:replay:${txid}`;
  const seen = await kv.get(key);
  if (seen) return false;
  await kv.put(key, "1", { expirationTtl: 90 * 24 * 3600 });
  return true;
}

/** Release a claim when the call failed before settlement (nothing broadcast). */
export async function releasePaymentTxid(env: X402Env, txid: string): Promise<void> {
  const kv = env.METER;
  if (!kv) return;
  await kv.delete(`trust:replay:${txid}`);
}