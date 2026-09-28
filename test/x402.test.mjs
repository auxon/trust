import { test } from "node:test";
import assert from "node:assert/strict";
import { P2PKH, Script, Transaction } from "@bsv/sdk";
import {
  b64decodeJson,
  b64encodeJson,
  buildRequirements,
  claimPaymentTxid,
  releasePaymentTxid,
  verifyBsvPayment,
} from "../src/x402.ts";

const PAY_TO = "1DHBH964yuvJnneuUe7EKFpVyJK1Vkz8Y4";

function fakeKV() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
  };
}

function txPaying(payTo, satoshis) {
  const tx = new Transaction();
  tx.addInput({
    sourceTXID: "ab".repeat(32),
    sourceOutputIndex: 0,
    unlockingScript: new Script(),
  });
  tx.addOutput({ lockingScript: new P2PKH().lock(payTo), satoshis });
  return tx.toHex();
}

test("buildRequirements produces the x402 v2 exact envelope", () => {
  const req = buildRequirements({
    url: "https://entangleit.com/trust/profile",
    description: "EntangleIT Trust/profile: 5 sats",
    satoshis: 5,
    payTo: PAY_TO,
    arcUrl: "https://arc.gorillapool.io/v1",
  });
  assert.equal(req.x402Version, 2);
  assert.equal(req.scheme, "exact");
  assert.equal(req.network, "bsv:mainnet");
  assert.equal(req.amount, "5");
  assert.equal(req.asset, "native:BSV");
  assert.equal(req.payTo, PAY_TO);
  assert.equal(req.extra.satoshis, "5");
  assert.equal(req.resource.url, "https://entangleit.com/trust/profile");
  const roundTrip = b64decodeJson(b64encodeJson(req));
  assert.deepEqual(roundTrip, req);
});

test("verifyBsvPayment accepts a tx paying the required amount", async () => {
  const req = buildRequirements({ url: "u", description: "d", satoshis: 5, payTo: PAY_TO, arcUrl: "a" });
  const payload = {
    x402Version: 2,
    scheme: "exact",
    network: "bsv:mainnet",
    txHex: txPaying(PAY_TO, 7),
    encoding: "raw-hex",
  };
  const res = await verifyBsvPayment(req, payload);
  assert.equal(res.success, true);
  assert.equal(res.amount, 7);
  assert.match(res.payer, /^bsv:input:ab/);
  assert.match(res.txid, /^[0-9a-f]{64}$/);
});

test("verifyBsvPayment rejects underpayment, wrong network, and garbage", async () => {
  const req = buildRequirements({ url: "u", description: "d", satoshis: 5, payTo: PAY_TO, arcUrl: "a" });
  const base = { x402Version: 2, scheme: "exact", network: "bsv:mainnet", encoding: "raw-hex" };
  const under = await verifyBsvPayment(req, { ...base, txHex: txPaying(PAY_TO, 4) });
  assert.deepEqual(under, { success: false, errorReason: "invalid_exact_bsv_payment_recipient_mismatch" });
  const wrongNet = await verifyBsvPayment(req, { ...base, network: "btc:mainnet", txHex: txPaying(PAY_TO, 5) });
  assert.equal(wrongNet.success, false);
  assert.equal(wrongNet.errorReason, "invalid_payload");
  const garbage = await verifyBsvPayment(req, { ...base, txHex: "zz".repeat(100) });
  assert.equal(garbage.success, false);
  assert.equal(garbage.errorReason, "invalid_payload");
});

test("one txid pays for exactly one call", async () => {
  const env = { METER: fakeKV() };
  assert.equal(await claimPaymentTxid(env, "deadbeef"), true);
  assert.equal(await claimPaymentTxid(env, "deadbeef"), false);
  await releasePaymentTxid(env, "deadbeef");
  assert.equal(await claimPaymentTxid(env, "deadbeef"), true);
});