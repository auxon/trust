import { test } from "node:test";
import assert from "node:assert/strict";
import {
  attestationObservation,
  ingestObservation,
  isAttestationLike,
  marketFromObservations,
  resolveMembers,
  spendFromObservations,
  verifySignedObject,
  workFromObservations,
} from "../src/ingest.ts";
import { memoryStore } from "../src/store.ts";

const obs = (kind, meta, over = {}) => ({
  id: `id:${kind}:${JSON.stringify(meta).length}`,
  subject: "account:1",
  source: "test",
  kind,
  ref: `${kind}:${JSON.stringify(meta).length}`,
  value: null,
  meta_json: JSON.stringify(meta),
  observed_at: Date.now(),
  ...over,
});

test("resolveMembers walks the undirected binding graph", () => {
  const bindings = [
    { a: "wallet:w1", b: "key:k1", proof: "agentpay:attestation", evidence: "", bound_at: 1, revoked_at: null },
    { a: "key:k1", b: "account:7", proof: "challenge", evidence: "", bound_at: 2, revoked_at: null },
    { a: "account:7", b: "key:dead", proof: "challenge", evidence: "", bound_at: 3, revoked_at: 42 },
  ];
  assert.deepEqual(resolveMembers(bindings, "wallet:w1"), ["account:7", "key:k1", "wallet:w1"]);
  assert.deepEqual(resolveMembers(bindings, "account:7"), ["account:7", "key:k1", "wallet:w1"]);
  assert.deepEqual(resolveMembers(bindings, "account:9"), ["account:9"]);
});

test("spendFromObservations takes the latest valid snapshot, malformed is absent", () => {
  const metrics = { settledPayments: 12, distinctServices: 4, spentCents: 80, refundedCents: 0 };
  assert.deepEqual(
    spendFromObservations([obs("attestation", { metrics }), obs("spend_snapshot", { metrics: { bogus: true } })]),
    metrics,
  );
  assert.equal(spendFromObservations([obs("spend_snapshot", { metrics: { bogus: true } })]), null);
  assert.equal(spendFromObservations([]), null);
});

test("workFromObservations merges reputation stats and bounty_paid observations", () => {
  const rep = obs("reputation", {
    reputation: { score: 700, provisional: false, slashes: 0, verifyPassRate: 0.9 },
    stats: { bountiesCompleted: 7 },
  });
  const work = workFromObservations([rep]);
  assert.equal(work.score, 700);
  assert.equal(work.completed, 7);

  const counted = workFromObservations([
    obs("reputation", { reputation: { score: 700 } }),
    obs("bounty_paid", {}, { ref: "b1" }),
    obs("bounty_paid", {}, { ref: "b1" }),
    obs("bounty_paid", {}, { ref: "b2" }),
  ]);
  assert.equal(counted.completed, 2);
  assert.equal(workFromObservations([]), null);
});

test("marketFromObservations counts distinct services and lost disputes", () => {
  const market = marketFromObservations([
    obs("payment_settled", { service: "a" }),
    obs("payment_settled", { service: "b" }),
    obs("gateway_call", { service: "a" }),
    obs("dispute_lost", {}),
  ]);
  assert.deepEqual(market, { services: 2, calls: 3, disputesLost: 1 });
});

test("observations are idempotent on (source, ref)", async () => {
  const store = memoryStore();
  const input = { subject: "account:1", source: "bounties", kind: "reputation", ref: "1:2026-09-21", value: 700 };
  assert.equal(await ingestObservation(store, input), true);
  assert.equal(await ingestObservation(store, input), false);
  assert.equal((await store.stats()).observations, 1);
  assert.equal((await store.listObservations(["account:1"], 10)).length, 1);
});

test("attestation shape is validated and keyed to the wallet", () => {
  const att = {
    v: 1,
    iss: "agentpay.entangleit.com",
    wallet: "w1",
    sub: "key:abc",
    issuedAt: "2026-09-20T00:00:00.000Z",
    expiresAt: "2026-10-20T00:00:00.000Z",
    metrics: { settledPayments: 12, distinctServices: 4, spentCents: 80, refundedCents: 0 },
  };
  assert.equal(isAttestationLike(att), true);
  assert.equal(isAttestationLike({ ...att, metrics: { settledPayments: "12" } }), false);
  const o = attestationObservation(att);
  assert.equal(o.subject, "wallet:w1");
  assert.equal(o.kind, "attestation");
  assert.equal(o.ref, "w1:2026-09-20T00:00:00.000Z");
});

test("verifySignedObject accepts canonical signatures and rejects tampering", async () => {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const payload = { wallet: "w1", sub: "key:abc", issuedAt: "2026-09-20T00:00:00.000Z" };
  const { stableStringify } = await import("../src/core.ts");
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    kp.privateKey,
    new TextEncoder().encode(stableStringify(payload)),
  );
  const b64 = Buffer.from(new Uint8Array(sig)).toString("base64url");
  assert.equal(await verifySignedObject(publicJwk, payload, b64), true);
  assert.equal(await verifySignedObject(publicJwk, { ...payload, wallet: "w2" }, b64), false);
});