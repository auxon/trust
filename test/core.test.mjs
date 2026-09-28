import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TERMS,
  signProfile,
  spendVerified,
  stableStringify,
  termsFor,
  verifyProfile,
  workVerified,
} from "../src/core.ts";

async function keypair() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return { kp, jwk, publicJwk };
}

function profile(over = {}) {
  return {
    v: 1,
    iss: "trust.entangleit.com",
    sub: "account:1",
    members: ["account:1"],
    issuedAt: "2026-09-21T00:00:00.000Z",
    expiresAt: "2026-09-22T00:00:00.000Z",
    level: "proven",
    score: 700,
    confidence: 0.5,
    axes: { spend: null, work: null, market: null },
    terms: { approvalMultiplier: 2, bondDiscountBps: 5000, discountCeilingBps: 1000 },
    reasons: [],
    ...over,
  };
}

const now = Date.parse("2026-09-21T00:00:00.000Z");

function goodSpend(over = {}) {
  return {
    settledPayments: 12,
    distinctServices: 4,
    distinctPayTo: 4,
    spentCents: 80,
    refundedCents: 0,
    firstPaymentAt: "2026-08-01T00:00:00.000Z",
    lastPaymentAt: "2026-09-20T00:00:00.000Z",
    ...over,
  };
}

test("stableStringify sorts keys recursively", () => {
  assert.equal(stableStringify({ b: 1, a: [2, { d: 1, c: 2 }] }), '{"a":[2,{"c":2,"d":1}],"b":1}');
  assert.equal(stableStringify(undefined), "null");
});

test("signProfile round-trips and tampering fails", async () => {
  const { jwk, publicJwk } = await keypair();
  const env = { TRUST_KEY_JWK: JSON.stringify(jwk) };
  const signed = await signProfile(env, profile());
  assert.equal(signed.alg, "ES256");
  assert.ok(signed.signature.length > 20);
  assert.equal(await verifyProfile(publicJwk, signed.profile, signed.signature), true);
  assert.equal(await verifyProfile(publicJwk, profile({ level: "elite" }), signed.signature), false);
  assert.equal(await verifyProfile(publicJwk, signed.profile, "AAAA"), false);
});

test("signing is disabled without a key", async () => {
  assert.equal(await signProfile({}, profile()), null);
});

test("spend gate mirrors the shipped thresholds", () => {
  assert.deepEqual(spendVerified(goodSpend(), now), { eligible: true, reason: "trusted_spender" });
  assert.equal(spendVerified(goodSpend({ settledPayments: 9 }), now).reason, "too_few_payments");
  assert.equal(spendVerified(goodSpend({ distinctServices: 2 }), now).reason, "too_few_services");
  assert.equal(spendVerified(goodSpend({ distinctServices: 2, distinctPayTo: 4 }), now).reason, "too_few_services");
  assert.equal(spendVerified(goodSpend({ distinctServices: 2, distinctPayTo: 2 }), now).reason, "too_few_services");
  assert.equal(spendVerified(goodSpend({ distinctServices: 3, distinctPayTo: 1 }), now).reason, "trusted_spender", "max(services, payees) rules");
  // Off-chain rail spend: the service is the counterparty, so four services
  // with no on-chain payee must still verify (the bug this guards).
  assert.deepEqual(
    spendVerified(goodSpend({ distinctPayTo: 1 }), now),
    { eligible: true, reason: "trusted_spender" },
  );
  assert.deepEqual(
    spendVerified({ ...goodSpend(), distinctPayTo: undefined }, now),
    { eligible: true, reason: "trusted_spender" },
  );
  assert.equal(spendVerified(goodSpend({ spentCents: 49 }), now).reason, "spend_too_low");
  assert.equal(spendVerified(goodSpend({ refundedCents: 1 }), now).reason, "has_refunds");
  const fresh = goodSpend({ firstPaymentAt: "2026-09-20T00:00:00.000Z" });
  assert.equal(spendVerified(fresh, now).reason, "wallet_too_new");
  assert.equal(spendVerified(null, now).reason, "no_attestation");
  assert.equal(spendVerified({ settledPayments: 12 }, now).reason, "bad_metrics");
});

test("work gate mirrors the shipped thresholds", () => {
  const good = { score: 650, provisional: false, slashes: 0, completed: 3 };
  assert.deepEqual(workVerified(good), { eligible: true, reason: "trusted_worker" });
  assert.equal(workVerified({ ...good, score: 649 }).reason, "score_too_low");
  assert.equal(workVerified({ ...good, provisional: true }).reason, "provisional");
  assert.equal(workVerified({ ...good, slashes: 1 }).reason, "has_slashes");
  assert.equal(workVerified(null).reason, "no_reputation");
});

test("terms step down on a hold band and never up", () => {
  assert.deepEqual(termsFor("proven"), TERMS.proven);
  assert.deepEqual(termsFor("proven", { flag: "review", probability: 0.5 }), TERMS.proven);
  assert.deepEqual(termsFor("proven", { flag: "hold", probability: 0.9 }), TERMS.building);
  assert.deepEqual(termsFor("new", { flag: "hold", probability: 0.9 }), TERMS.new);
});