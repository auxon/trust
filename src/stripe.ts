/**
 * Stripe integration, fetch-only (no SDK, no node deps). Same shape as the
 * other EntangleIT connectors; the account id travels as client_reference_id
 * so a completed payment credits the right account.
 */
import type { Plan } from "./plans.ts";

export interface StripeEnv {
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRICE_PACK?: string;
  STRIPE_PRICE_PRO?: string;
  STRIPE_PRICE_B2B?: string;
  PUBLIC_BASE?: string;
}

export function stripeConfigured(env: StripeEnv): boolean {
  return Boolean(env.STRIPE_SECRET_KEY);
}

function publicBase(env: StripeEnv): string {
  return (env.PUBLIC_BASE ?? "https://entangleit.com/trust").replace(/\/$/, "");
}

export async function createCheckoutSession(
  env: StripeEnv,
  opts: { accountId: string; plan: Plan },
): Promise<{ url: string } | { error: string }> {
  if (!env.STRIPE_SECRET_KEY) return { error: "billing not configured" };
  const base = publicBase(env);
  const form = new URLSearchParams();
  form.set("mode", opts.plan.mode);
  form.set("success_url", `${base}/thanks?session={CHECKOUT_SESSION_ID}`);
  form.set("cancel_url", `${base}/`);
  form.set("client_reference_id", opts.accountId);
  form.set("metadata[account_id]", opts.accountId);
  form.set("metadata[plan]", opts.plan.id);
  form.set("line_items[0][quantity]", "1");
  const priceId = opts.plan.priceEnv ? env[opts.plan.priceEnv] : undefined;
  if (priceId) {
    form.set("line_items[0][price]", priceId);
  } else {
    form.set("line_items[0][price_data][currency]", "usd");
    form.set("line_items[0][price_data][unit_amount]", String(opts.plan.amountCents));
    form.set("line_items[0][price_data][product_data][name]", opts.plan.label);
    if (opts.plan.mode === "subscription") {
      form.set("line_items[0][price_data][recurring][interval]", "month");
    }
  }
  const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form,
  });
  const body = (await res.json().catch(() => null)) as { url?: string; error?: { message?: string } } | null;
  if (!res.ok) return { error: body?.error?.message ?? `stripe ${res.status}` };
  if (!body?.url) return { error: "stripe returned no checkout url" };
  return { url: body.url };
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Verify a `Stripe-Signature` header: HMAC-SHA256 of `${t}.${payload}`. */
export async function verifyWebhookSignature(
  secret: string,
  payload: string,
  header: string,
  toleranceSec = 300,
  nowMs = Date.now(),
): Promise<boolean> {
  const parts: Record<string, string> = {};
  for (const piece of header.split(",")) {
    const idx = piece.indexOf("=");
    if (idx > 0) parts[piece.slice(0, idx).trim()] = piece.slice(idx + 1).trim();
  }
  const t = Number(parts.t);
  const v1 = parts.v1 ?? "";
  if (!Number.isFinite(t) || !v1) return false;
  if (Math.abs(nowMs / 1000 - t) > toleranceSec) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${t}.${payload}`));
  const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return timingSafeEqual(hex, v1);
}

export interface StripeEvent {
  id: string;
  type: string;
  data: { object: Record<string, unknown> };
}

export function parseEvent(payload: string): StripeEvent | null {
  try {
    const parsed = JSON.parse(payload) as StripeEvent;
    if (!parsed || typeof parsed !== "object" || typeof parsed.type !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}