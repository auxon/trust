import { test } from "node:test";
import assert from "node:assert/strict";
import { signProfile, verifyProfile } from "../src/core.ts";
import { handleMessage, SERVER_INFO, TOOLS } from "../src/mcp.ts";
import { memoryStore } from "../src/store.ts";

function profile() {
  return {
    v: 1,
    iss: "trust.entangleit.com",
    sub: "account:1",
    members: ["account:1"],
    issuedAt: "2026-09-21T00:00:00.000Z",
    expiresAt: "2026-09-22T00:00:00.000Z",
    level: "proven",
    score: 700,
    confidence: 0.6,
    axes: {
      spend: { settledPayments: 12, distinctServices: 4, spentCents: 80, refundedCents: 0 },
      work: { score: 700, provisional: false, slashes: 0, completed: 2 },
      market: { services: 0, calls: 0, disputesLost: 0 },
    },
    terms: { approvalMultiplier: 2, bondDiscountBps: 5000, discountCeilingBps: 1000 },
    reasons: ["spend_verified", "work_verified"],
  };
}

async function context(over = {}) {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const env = { TRUST_KEY_JWK: JSON.stringify(jwk) };
  const signed = await signProfile(env, profile());
  const store = memoryStore();
  const account = await store.ensureAccount("acct:test", null, 0);
  return {
    store,
    account,
    now: () => Date.now(),
    freeDaily: 5,
    profile: async () => signed,
    verify: async ({ profile: p, signature }) => ({
      valid: await verifyProfile(publicJwk, p, signature),
      expired: false,
    }),
    bind: async () => ({ ok: true, a: "key:abc", b: "account:1", proof: "challenge" }),
    leaderboard: async () => [
      { subject: "account:1", level: "proven", updated_at: Date.now() },
      { subject: "account:2", level: "building", updated_at: Date.now() - 1000 },
    ],
    ...over,
  };
}

const rpc = (ctx, msg) => handleMessage(msg, ctx);

test("initialize identifies the server and advertises tools", async () => {
  const ctx = await context();
  const res = await rpc(ctx, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
  assert.equal(res.result.serverInfo, SERVER_INFO);
  assert.equal(res.result.protocolVersion, "2025-06-18");
  assert.equal((await rpc(ctx, { jsonrpc: "2.0", id: 2, method: "tools/list" })).result.tools.length, TOOLS.length);
  assert.equal(await rpc(ctx, { jsonrpc: "2.0", method: "notifications/initialized" }), null);
});

test("trust_profile returns a signed profile and records the call", async () => {
  const ctx = await context();
  const res = await rpc(ctx, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "trust_profile", arguments: { subject: "account:1" } },
  });
  assert.equal(res.result.structuredContent.profile.level, "proven");
  assert.match(res.result.content[0].text, /account:1 → proven/);
  assert.equal((await ctx.store.stats()).calls, 1);
});

test("trust_terms returns only the terms block", async () => {
  const ctx = await context();
  const res = await rpc(ctx, {
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "trust_terms", arguments: { subject: "account:1" } },
  });
  assert.deepEqual(res.result.structuredContent.terms, {
    approvalMultiplier: 2,
    bondDiscountBps: 5000,
    discountCeilingBps: 1000,
  });
  assert.equal(res.result.structuredContent.level, "proven");
});

test("trust_verify accepts the real signature and rejects tampering", async () => {
  const ctx = await context();
  const signed = await ctx.profile("account:1");
  const ok = await rpc(ctx, {
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "trust_verify", arguments: { profile: signed.profile, signature: signed.signature } },
  });
  assert.equal(ok.result.structuredContent.valid, true);
  const tampered = await rpc(ctx, {
    jsonrpc: "2.0",
    id: 6,
    method: "tools/call",
    params: {
      name: "trust_verify",
      arguments: { profile: { ...signed.profile, level: "elite" }, signature: signed.signature },
    },
  });
  assert.equal(tampered.result.structuredContent.valid, false);
});

test("the free tier gates spend but not verification", async () => {
  const ctx = await context({ freeDaily: 1 });
  const first = await rpc(ctx, {
    jsonrpc: "2.0",
    id: 7,
    method: "tools/call",
    params: { name: "trust_terms", arguments: { subject: "account:1" } },
  });
  assert.ok(!first.result.isError);
  const second = await rpc(ctx, {
    jsonrpc: "2.0",
    id: 8,
    method: "tools/call",
    params: { name: "trust_terms", arguments: { subject: "account:1" } },
  });
  assert.equal(second.result.isError, true);
  assert.match(second.result.content[0].text, /Daily free limit/);
  const verify = await rpc(ctx, {
    jsonrpc: "2.0",
    id: 9,
    method: "tools/call",
    params: { name: "trust_verify", arguments: { profile: {}, signature: "x" } },
  });
  assert.ok(!verify.result.isError);
});

test("credits bypass the free tier", async () => {
  const ctx = await context({ freeDaily: 0 });
  await ctx.store.addCredits(ctx.account.id, 2);
  const res = await rpc(ctx, {
    jsonrpc: "2.0",
    id: 10,
    method: "tools/call",
    params: { name: "trust_profile", arguments: { subject: "account:1" } },
  });
  assert.ok(!res.result.isError);
  assert.equal((await ctx.store.getAccount(ctx.account.id)).credits, 1);
});

test("leaderboard ranks by level and status reports counters", async () => {
  const ctx = await context();
  const board = await rpc(ctx, { jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "trust_leaderboard", arguments: { limit: 5 } } });
  assert.equal(board.result.structuredContent.items[0].subject, "account:1");
  const status = await rpc(ctx, { jsonrpc: "2.0", id: 12, method: "tools/call", params: { name: "status", arguments: {} } });
  assert.equal(typeof status.result.structuredContent.stats.subjects, "number");
});

test("billing lists plans and unknown tools error", async () => {
  const ctx = await context();
  const billing = await rpc(ctx, { jsonrpc: "2.0", id: 13, method: "tools/call", params: { name: "billing", arguments: {} } });
  assert.equal(billing.result.structuredContent.plans.length, 3);
  const unknown = await rpc(ctx, { jsonrpc: "2.0", id: 14, method: "tools/call", params: { name: "nope", arguments: {} } });
  assert.equal(unknown.error.code, -32602);
});