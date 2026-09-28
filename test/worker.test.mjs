import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";
import { signingKeyId, verifyProfile } from "../src/core.ts";
import { b64decodeJson } from "../src/x402.ts";

const PAY_TO = "1DHBH964yuvJnneuUe7EKFpVyJK1Vkz8Y4";
const INTERNAL = "s3cret";

function fakeKV() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
  };
}

async function makeEnv(over = {}) {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  return {
    METER: fakeKV(),
    PUBLIC_BASE: "https://entangleit.com/trust",
    PRICE_SATS: "5",
    PAY_TO,
    ARC_URL: "https://arc.gorillapool.io/v1",
    TRUST_INGEST_SECRET: INTERNAL,
    TRUST_KEY_JWK: JSON.stringify(jwk),
    RATCHET_DAYS: "0",
    FREE_DAILY_CALLS: "5",
    ...over,
  };
}

const call = (env, path, init) => worker.fetch(new Request(`https://entangleit.com/trust${path}`, init), env);

const jsonPost = (body, headers = {}) => ({
  method: "POST",
  headers: { "content-type": "application/json", ...headers },
  body: JSON.stringify(body),
});

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

const oldIso = (days) => new Date(Date.now() - days * 86_400_000).toISOString();

async function fundedEnv() {
  const env = await makeEnv();
  const spend = {
    settledPayments: 12,
    distinctServices: 4,
    distinctPayTo: 4,
    spentCents: 80,
    refundedCents: 0,
    firstPaymentAt: oldIso(30),
    lastPaymentAt: oldIso(1),
  };
  const res = await call(env, "/v1/ingest", jsonPost(
    {
      observations: [
        { subject: "account:42", source: "test", kind: "spend_snapshot", ref: "42:day1", meta: { metrics: spend } },
      ],
      reputation: {
        account: 42,
        reputation: { score: 700, provisional: false, slashes: 0, verifyPassRate: 0.95 },
        stats: { bountiesCompleted: 2 },
      },
    },
    { "x-trust-internal": INTERNAL },
  ));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.observations, 1);
  assert.equal(body.reputations, 1);
  return env;
}

test("health, key, docs, and status", async () => {
  const env = await makeEnv();
  const health = await (await call(env, "/health")).json();
  assert.equal(health.ok, true);
  assert.equal(health.signing_configured, true);
  const key = await (await call(env, "/v1/key")).json();
  assert.equal(key.alg, "ES256");
  assert.ok(key.publicJwk.x);
  const docs = await call(env, "/docs");
  assert.match(await docs.text(), /Levels and terms/);
  const status = await (await call(env, "/v1/status")).json();
  assert.equal(typeof status.stats.subjects, "number");
});

test("ingest without the internal secret is rejected", async () => {
  const env = await makeEnv();
  const res = await call(env, "/v1/ingest", jsonPost({ observations: [] }));
  assert.equal(res.status, 401);
});

test("verified spend and work produce a signed proven profile with terms", async () => {
  const env = await fundedEnv();
  const res = await call(env, "/v1/profile/account:42");
  assert.equal(res.status, 200);
  const { profile, signature, keyId } = await res.json();
  assert.equal(profile.level, "proven");
  assert.equal(profile.terms.approvalMultiplier, 2);
  assert.equal(profile.terms.bondDiscountBps, 5000);
  const key = await (await call(env, "/v1/key")).json();
  assert.equal(keyId, key.keyId);
  assert.equal(await verifyProfile(key.publicJwk, profile, signature), true);

  const verified = await (await call(env, "/v1/verify", jsonPost({ profile, signature }))).json();
  assert.equal(verified.valid, true);
  const tampered = await (await call(env, "/v1/verify", jsonPost({ profile: { ...profile, level: "elite" }, signature }))).json();
  assert.equal(tampered.valid, false);
});

test("badge and public page render for a subject", async () => {
  const env = await fundedEnv();
  const badge = await call(env, "/badge/account:42.svg");
  assert.equal(badge.headers.get("content-type"), "image/svg+xml");
  assert.match(await badge.text(), /proven \d+/);
  const page = await call(env, "/p/account:42");
  assert.match(await page.text(), /Signed by/);
});

test("an unknown subject is signed as new, not guessed", async () => {
  const env = await makeEnv();
  const { profile } = await (await call(env, "/v1/profile/account:999")).json();
  assert.equal(profile.level, "new");
  assert.equal(profile.terms.approvalMultiplier, 1);
});

test("paid profile returns a 402 challenge without a signature", async () => {
  const env = await makeEnv();
  const res = await call(env, "/profile", jsonPost({ subject: "account:42" }));
  assert.equal(res.status, 402);
  const requirements = b64decodeJson(res.headers.get("PAYMENT-REQUIRED"));
  assert.equal(requirements.amount, "5");
  assert.equal(requirements.payTo, PAY_TO);
  assert.equal(requirements.resource.url, "https://entangleit.com/trust/profile");
});

test("internal callers can bind a key to an account with a signed challenge", async () => {
  const env = await makeEnv();
  const challenge = await (await call(env, "/v1/bind/challenge")).json();
  assert.ok(challenge.nonce);

  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const keySubject = `key:${await signingKeyId(publicJwk)}`;
  const message = `bind:${keySubject}:account:42:${challenge.nonce}`;
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    kp.privateKey,
    new TextEncoder().encode(message),
  );
  const body = { other: "account:42", jwk: publicJwk, nonce: challenge.nonce, signature: b64url(new Uint8Array(sig)) };
  const bound = await call(env, "/v1/bind", jsonPost(body, { "x-trust-internal": INTERNAL }));
  assert.equal(bound.status, 200);
  const result = await bound.json();
  assert.equal(result.ok, true);
  assert.equal(result.a, keySubject);
  assert.equal(result.proof, "challenge");

  const replay = await call(env, "/v1/bind", jsonPost(body, { "x-trust-internal": INTERNAL }));
  assert.equal(replay.status, 400);
});

test("operator bindings link a BSV key without a challenge", async () => {
  const env = await makeEnv();
  const key = "key:0379451028247f7ddba88ef272d47e2b0d72b47942d0b4081cb13a4a175340b135";
  const bound = await call(env, "/v1/bind", jsonPost({ key, other: "wallet:apw_test" }, { "x-trust-internal": INTERNAL }));
  assert.equal(bound.status, 200);
  const body = await bound.json();
  assert.equal(body.ok, true);
  assert.equal(body.a, key);
  assert.equal(body.proof, "operator");
  // The subjects resolve together: the key's profile carries the wallet.
  const profile = await (await call(env, `/v1/profile/${encodeURIComponent(key)}`)).json();
  assert.ok(profile.profile.members.includes("wallet:apw_test"), "binding merges members");
  // Same request without the secret is not a binding (no jwk/signature).
  const env2 = await makeEnv();
  const denied = await call(env2, "/v1/bind", jsonPost({ key, other: "wallet:apw_test" }));
  assert.equal(denied.status, 400);
});

test("account bindings without the internal secret fail closed", async () => {
  const env = await makeEnv();
  const challenge = await (await call(env, "/v1/bind/challenge")).json();
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const keySubject = `key:${await signingKeyId(publicJwk)}`;
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    kp.privateKey,
    new TextEncoder().encode(`bind:${keySubject}:account:42:${challenge.nonce}`),
  );
  const res = await call(env, "/v1/bind", jsonPost({ other: "account:42", jwk: publicJwk, nonce: challenge.nonce, signature: b64url(new Uint8Array(sig)) }));
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /x-trust-internal/);
});

test("reconcile reports no DB in memory mode instead of pretending", async () => {
  const env = await makeEnv();
  const res = await (await call(env, "/v1/reconcile", jsonPost({}, { "x-trust-internal": INTERNAL }))).json();
  assert.equal(res.wallets, 0);
  assert.match(res.errors[0], /no DB bound/);
});

test("MCP is reachable at the mount path", async () => {
  const env = await makeEnv();
  const res = await call(env, "/mcp", jsonPost({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }));
  const body = await res.json();
  assert.equal(body.result.serverInfo.name, "entangleit-trust");
});