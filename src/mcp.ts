/**
 * MCP server surface (Streamable HTTP, JSON-RPC 2.0) for EntangleIT Trust.
 *
 * Tools: trust_profile, trust_terms, trust_verify, trust_bind,
 * trust_leaderboard, billing, status. Storage, signing, and binding are
 * injected by the Worker so tests need no network.
 */
import { levelIndex, type SignedProfile, type TrustLevel, type TrustProfile } from "./core.ts";
import { PLANS, planById } from "./plans.ts";
import type { Account, SubjectState, TrustStore } from "./store.ts";

export const SERVER_INFO = { name: "entangleit-trust", version: "0.1.0" };
export const SUPPORTED_PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"];
export const LATEST_PROTOCOL = SUPPORTED_PROTOCOLS[0]!;

export interface ToolContext {
  store: TrustStore;
  account: Account;
  now: () => number;
  freeDaily: number;
  /** Operator token: bypasses the free-tier/credit gate (acceptance runs). */
  unlimited?: boolean;
  profile: (subject: string) => Promise<SignedProfile | null>;
  verify: (input: { profile: TrustProfile; signature: string }) => Promise<{ valid: boolean; expired: boolean }>;
  bind: (input: Record<string, unknown>) => Promise<{ ok: boolean; error?: string; a?: string; b?: string; proof?: string }>;
  leaderboard: (limit: number) => Promise<SubjectState[]>;
  createCheckout?: (planId: string) => Promise<{ url: string } | { error: string }>;
}

export const TOOLS = [
  {
    name: "trust_profile",
    description:
      "Get the signed trust profile for a subject: level (new/building/proven/trusted/elite), score, " +
      "spend and work axes, and the terms it unlocks (approval multiplier, bond discount, discount ceiling). " +
      "Subjects: wallet:<id>, account:<n>, or key:<thumbprint>.",
    inputSchema: {
      type: "object",
      properties: { subject: { type: "string", description: "Subject id, e.g. account:1 or wallet:<uuid>" } },
      required: ["subject"],
      additionalProperties: false,
    },
  },
  {
    name: "trust_terms",
    description:
      "Get only the terms block for a subject — cheaper and shorter than trust_profile. Use before hiring, " +
      "bonding, or pricing: approvalMultiplier, bondDiscountBps, discountCeilingBps, level, expiresAt.",
    inputSchema: {
      type: "object",
      properties: { subject: { type: "string", description: "Subject id, e.g. account:1 or wallet:<uuid>" } },
      required: ["subject"],
      additionalProperties: false,
    },
  },
  {
    name: "trust_verify",
    description:
      "Verify a signed trust profile offline-style: returns whether the signature is valid against the issuer key " +
      "and whether the profile is expired. Free; no credit is spent.",
    inputSchema: {
      type: "object",
      properties: {
        profile: { type: "object", description: "The profile object as returned by trust_profile" },
        signature: { type: "string", description: "Base64url ES256 signature over the canonical profile JSON" },
      },
      required: ["profile", "signature"],
      additionalProperties: false,
    },
  },
  {
    name: "trust_bind",
    description:
      "Bind two subjects with two-sided proof: a P-256 key (jwk) signs a challenge nonce, and (for wallet " +
      "bindings) a signed agentpay attestation ties the wallet to the key's subject. Free; bindings only merge " +
      "evidence, they never grant terms on their own.",
    inputSchema: {
      type: "object",
      properties: {
        other: { type: "string", description: "The other subject to bind, e.g. wallet:<id> or account:<n>" },
        jwk: { type: "object", description: "Public P-256 JWK of the key proving control" },
        nonce: { type: "string", description: "Nonce from GET /v1/bind/challenge?key=..." },
        signature: { type: "string", description: "Base64url ES256 signature over 'bind:<key>:<other>:<nonce>'" },
        attestation: { type: "object", description: "Optional agentpay attestation binding the wallet to the key" },
        attestationSignature: { type: "string", description: "Signature for the attestation" },
      },
      required: ["other", "jwk", "nonce", "signature"],
      additionalProperties: false,
    },
  },
  {
    name: "trust_leaderboard",
    description:
      "Recent subject states ranked by trust level and score — the cheap ground truth for who has earned what. Free.",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number", description: "How many rows (1-100, default 20)" } },
      additionalProperties: false,
    },
  },
  {
    name: "billing",
    description:
      "Show Trust plans and your plan/credits, or start a Stripe Link checkout to buy credits (pack25) or " +
      "subscribe (pro, b2b). Call without arguments to see plans and your balance.",
    inputSchema: {
      type: "object",
      properties: {
        plan: { type: "string", enum: ["pack25", "pro", "b2b"], description: "Plan to buy; omit to see plans and your balance" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "status",
    description: "Service counters and configuration: subjects, observations, bindings, profiles, free daily limit.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
] as const;

function result(id: unknown, value: unknown): Record<string, unknown> {
  return { jsonrpc: "2.0", id: id ?? null, result: value };
}

function error(id: unknown, code: number, message: string, data?: unknown): Record<string, unknown> {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

export function toolText(text: string, structured?: unknown, isError = false): Record<string, unknown> {
  return {
    content: [{ type: "text", text }],
    ...(structured === undefined ? {} : { structuredContent: structured }),
    ...(isError ? { isError: true } : {}),
  };
}

function subjectArg(args: Record<string, unknown>): string {
  const subject = typeof args.subject === "string" ? args.subject.trim() : "";
  return subject;
}

/** Enforce the free tier/credits. Returns an error message or null when allowed. */
async function gate(ctx: ToolContext): Promise<string | null> {
  if (ctx.unlimited) return null;
  const account = (await ctx.store.getAccount(ctx.account.id)) ?? ctx.account;
  const usedToday = await ctx.store.countCallsSince(ctx.account.id, ctx.now() - 24 * 60 * 60 * 1000);
  if (account.credits <= 0 && usedToday >= ctx.freeDaily) {
    return `Daily free limit reached (${ctx.freeDaily}/day). Buy credits with the billing tool to continue.`;
  }
  return null;
}

async function spendCredit(ctx: ToolContext, kind: string, subject: string | null): Promise<void> {
  if (!ctx.unlimited) {
    const account = (await ctx.store.getAccount(ctx.account.id)) ?? ctx.account;
    if (account.credits > 0) await ctx.store.decrementCredit(ctx.account.id);
  }
  await ctx.store.recordCall({
    id: crypto.randomUUID(),
    account_id: ctx.account.id,
    kind,
    subject,
    created_at: ctx.now(),
  });
}

async function toolProfile(args: Record<string, unknown>, ctx: ToolContext): Promise<Record<string, unknown>> {
  const subject = subjectArg(args);
  if (!subject) return toolText("subject is required, e.g. account:1 or wallet:<uuid>", undefined, true);
  const blocked = await gate(ctx);
  if (blocked) return toolText(blocked, undefined, true);
  const signed = await ctx.profile(subject);
  if (!signed) return toolText("Trust signing is not configured on this deployment.", undefined, true);
  await spendCredit(ctx, "profile", subject);
  const p = signed.profile;
  return toolText(
    `${subject} → ${p.level} (score ${p.score}, conf ${p.confidence}) · approval ×${p.terms.approvalMultiplier} · ` +
      `bond −${p.terms.bondDiscountBps / 100}% · discount ceiling ${p.terms.discountCeilingBps / 100}%\n` +
      `expires ${p.expiresAt}${p.band ? ` · band ${p.band.flag} (p=${p.band.probability.toFixed(2)})` : ""}`,
    signed,
  );
}

async function toolTerms(args: Record<string, unknown>, ctx: ToolContext): Promise<Record<string, unknown>> {
  const subject = subjectArg(args);
  if (!subject) return toolText("subject is required, e.g. account:1 or wallet:<uuid>", undefined, true);
  const blocked = await gate(ctx);
  if (blocked) return toolText(blocked, undefined, true);
  const signed = await ctx.profile(subject);
  if (!signed) return toolText("Trust signing is not configured on this deployment.", undefined, true);
  await spendCredit(ctx, "terms", subject);
  const p = signed.profile;
  const terms = {
    subject: p.sub,
    level: p.level,
    score: p.score,
    confidence: p.confidence,
    terms: p.terms,
    expiresAt: p.expiresAt,
  };
  return toolText(
    `${p.level}: approval ×${p.terms.approvalMultiplier}, bond −${p.terms.bondDiscountBps / 100}%, discount ceiling ${p.terms.discountCeilingBps / 100}%`,
    terms,
  );
}

async function toolVerify(args: Record<string, unknown>, ctx: ToolContext): Promise<Record<string, unknown>> {
  const profile = args.profile as TrustProfile | undefined;
  const signature = typeof args.signature === "string" ? args.signature : "";
  if (!profile || typeof profile !== "object" || !signature) {
    return toolText("profile and signature are required", undefined, true);
  }
  const verdict = await ctx.verify({ profile, signature });
  return toolText(
    verdict.valid ? (verdict.expired ? "Valid signature, but the profile is expired." : "Valid and unexpired.") : "Invalid signature.",
    verdict,
  );
}

async function toolBind(args: Record<string, unknown>, ctx: ToolContext): Promise<Record<string, unknown>> {
  const res = await ctx.bind(args);
  if (!res.ok) return toolText(`Bind failed: ${res.error ?? "unknown error"}`, res, true);
  return toolText(`Bound ${res.a} ↔ ${res.b} (${res.proof}).`, res);
}

async function toolLeaderboard(args: Record<string, unknown>, ctx: ToolContext): Promise<Record<string, unknown>> {
  const raw = Number(args.limit ?? 20);
  const limit = Number.isFinite(raw) ? Math.max(1, Math.min(100, Math.round(raw))) : 20;
  const states = await ctx.leaderboard(limit * 4);
  const ranked = states
    .sort((a, b) => levelIndex(b.level as TrustLevel) - levelIndex(a.level as TrustLevel) || b.updated_at - a.updated_at)
    .slice(0, limit)
    .map((s) => ({ subject: s.subject, level: s.level, updated_at: s.updated_at }));
  return toolText(`${ranked.length} subject(s)`, { items: ranked });
}

async function toolBilling(args: Record<string, unknown>, ctx: ToolContext): Promise<Record<string, unknown>> {
  const account = (await ctx.store.getAccount(ctx.account.id)) ?? ctx.account;
  const current = { plan: account.plan, credits: account.credits, free_daily: ctx.freeDaily };
  const planId = typeof args.plan === "string" ? args.plan.trim() : "";
  if (!planId) {
    return toolText(`Plan ${current.plan} · ${current.credits} credits · ${current.free_daily} free/day.`, {
      account: current,
      plans: PLANS.map((p) => ({
        id: p.id,
        label: p.label,
        description: p.description,
        amount_cents: p.amountCents,
        credits: p.credits,
        mode: p.mode,
      })),
    });
  }
  const plan = planById(planId);
  if (!plan) return toolText(`Unknown plan: ${planId}`, undefined, true);
  if (!ctx.createCheckout) return toolText("Billing is not configured on this deployment yet.", undefined, true);
  const res = await ctx.createCheckout(plan.id);
  if ("error" in res) return toolText(`Could not start checkout: ${res.error}`, undefined, true);
  const price = `$${(plan.amountCents / 100).toFixed(2)}${plan.mode === "subscription" ? "/mo" : ""}`;
  return toolText(
    `Checkout ready for ${plan.label} (${price}, ${plan.credits} lookups). Pay with Stripe Link; credits apply automatically.`,
    { checkout_url: res.url, plan: plan.id, credits: plan.credits },
  );
}

async function toolStatus(_args: Record<string, unknown>, ctx: ToolContext): Promise<Record<string, unknown>> {
  const stats = await ctx.store.stats();
  return toolText(
    `${stats.subjects} subjects · ${stats.observations} observations · ${stats.bindings} bindings · ${stats.profiles} profiles`,
    { stats, free_daily: ctx.freeDaily },
  );
}

const HANDLERS: Record<string, (args: Record<string, unknown>, ctx: ToolContext) => Promise<Record<string, unknown>>> = {
  trust_profile: toolProfile,
  trust_terms: toolTerms,
  trust_verify: toolVerify,
  trust_bind: toolBind,
  trust_leaderboard: toolLeaderboard,
  billing: toolBilling,
  status: toolStatus,
};

/** Dispatch one JSON-RPC message. Returns null for notifications. */
export async function handleMessage(msg: unknown, ctx: ToolContext): Promise<Record<string, unknown> | null> {
  if (msg === null || typeof msg !== "object" || Array.isArray(msg)) {
    return error(null, -32600, "invalid request");
  }
  const m = msg as Record<string, unknown>;
  const id = m.id ?? null;
  const method = typeof m.method === "string" ? m.method : "";
  const params = (m.params ?? {}) as Record<string, unknown>;
  const isNotification = !("id" in m);

  if (m.jsonrpc !== "2.0" || !method) return error(id, -32600, "invalid request");

  try {
    switch (method) {
      case "initialize": {
        const asked = typeof params.protocolVersion === "string" ? params.protocolVersion : "";
        const protocolVersion = SUPPORTED_PROTOCOLS.includes(asked) ? asked : LATEST_PROTOCOL;
        return result(id, {
          protocolVersion,
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions:
            "EntangleIT Trust turns verified history into terms. Ask for a subject's profile or terms before " +
            "hiring, bonding, or pricing. Levels are deterministic (spend + work + time), climb one step per " +
            "ratchet window, and drop immediately on bad evidence. Signatures verify offline with GET /v1/key.",
        });
      }
      case "notifications/initialized":
      case "notifications/cancelled":
        return null;
      case "ping":
        return result(id, {});
      case "tools/list":
        return result(id, { tools: TOOLS });
      case "tools/call": {
        const name = typeof params.name === "string" ? params.name : "";
        const args = (params.arguments && typeof params.arguments === "object" ? params.arguments : {}) as Record<string, unknown>;
        const handler = HANDLERS[name];
        if (!handler) return error(id, -32602, `unknown tool: ${name}`);
        return result(id, await handler(args, ctx));
      }
      default:
        return error(id, -32601, `method not found: ${method}`);
    }
  } catch (e) {
    if (isNotification) return null;
    return error(id, -32603, e instanceof Error ? e.message : "internal error");
  }
}