import { test } from "node:test";
import assert from "node:assert/strict";
import { TERMS } from "../src/core.ts";
import { computeProfile, ratchetLevel } from "../src/score.ts";

const now = Date.parse("2026-09-21T00:00:00.000Z");
const daysAgo = (n) => new Date(now - n * 86_400_000).toISOString();

const spend = (over = {}) => ({
  settledPayments: 12,
  distinctServices: 4,
  distinctPayTo: 4,
  spentCents: 80,
  refundedCents: 0,
  firstPaymentAt: daysAgo(30),
  lastPaymentAt: daysAgo(1),
  ...over,
});

const work = (over = {}) => ({
  score: 700,
  provisional: false,
  slashes: 0,
  completed: 2,
  verifyPassRate: 0.95,
  ...over,
});

const base = { subject: "account:1", members: ["account:1"], market: null, now, ratchetDays: 7 };

test("no evidence is new; one axis is building; both axes is proven", () => {
  assert.equal(computeProfile({ ...base, spend: null, work: null }).level, "new");
  assert.equal(computeProfile({ ...base, spend: spend(), work: null }).level, "building");
  assert.equal(computeProfile({ ...base, spend: null, work: work() }).level, "building");
  assert.equal(computeProfile({ ...base, spend: spend(), work: work() }).level, "proven");
});

test("trusted needs volume, counterparties, time, and a clean pass rate", () => {
  const strong = spend({ settledPayments: 50, distinctPayTo: 10, spentCents: 500, firstPaymentAt: daysAgo(40) });
  const strongWork = work({ completed: 5, verifyPassRate: 0.92 });
  assert.equal(computeProfile({ ...base, spend: strong, work: strongWork }).level, "trusted");

  const tooNew = spend({ settledPayments: 50, distinctPayTo: 10, spentCents: 500, firstPaymentAt: daysAgo(10) });
  assert.equal(computeProfile({ ...base, spend: tooNew, work: strongWork }).level, "proven");

  const lowRate = work({ completed: 5, verifyPassRate: 0.5 });
  assert.equal(computeProfile({ ...base, spend: strong, work: lowRate }).level, "proven");
});

test("elite needs the long track record", () => {
  const elite = spend({ settledPayments: 200, distinctPayTo: 25, spentCents: 2500, firstPaymentAt: daysAgo(100) });
  const eliteWork = work({ completed: 20, verifyPassRate: 0.96, score: 850 });
  const profile = computeProfile({ ...base, spend: elite, work: eliteWork });
  assert.equal(profile.level, "elite");
  assert.deepEqual(profile.terms, TERMS.elite);
});

test("ratchet: first sight lands earned, upgrades are one step per window, drops are immediate", () => {
  assert.equal(ratchetLevel("elite", undefined, undefined, now, 7), "elite");
  assert.equal(ratchetLevel("elite", "proven", now, now, 7), "proven");
  assert.equal(ratchetLevel("elite", "proven", now - 8 * 86_400_000, now, 7), "trusted");
  assert.equal(ratchetLevel("building", "trusted", now, now, 7), "building");

  const elite = spend({ settledPayments: 200, distinctPayTo: 25, spentCents: 2500, firstPaymentAt: daysAgo(100) });
  const eliteWork = work({ completed: 20, verifyPassRate: 0.96 });
  const held = computeProfile({
    ...base,
    spend: elite,
    work: eliteWork,
    storedLevel: "proven",
    lastUpgradeAt: now,
  });
  assert.equal(held.level, "proven");
});

test("a hold band steps terms down without changing the level", () => {
  const profile = computeProfile({
    ...base,
    spend: spend(),
    work: work(),
    band: { flag: "hold", probability: 0.9 },
  });
  assert.equal(profile.level, "proven");
  assert.deepEqual(profile.terms, TERMS.building);
  assert.equal(profile.band.flag, "hold");
});

test("profile carries score, confidence, expiry, and sorted members", () => {
  const profile = computeProfile({ ...base, members: ["account:1", "key:abc"], spend: spend(), work: work() });
  assert.ok(profile.score > 0 && profile.score <= 1000);
  assert.ok(profile.confidence > 0.2 && profile.confidence <= 0.99);
  assert.deepEqual(profile.members, ["account:1", "key:abc"]);
  assert.equal(Date.parse(profile.expiresAt) - Date.parse(profile.issuedAt), 86_400_000);
});