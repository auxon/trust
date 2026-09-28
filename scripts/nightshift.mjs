/**
 * Nightshift — the unattended worker that earns trust in public.
 *
 * It claims a bounty, submits a deterministic deliverable, gets paid into its
 * agentpay balance, buys an x402 service with the earnings, and reports how
 * its signed trust terms moved. Small real mainnet amounts, operator-capped.
 *
 *   AGENTPAY_KEY=agp_… node scripts/nightshift.mjs            # plan + current trust (no writes)
 *   AGENTPAY_KEY=agp_… node scripts/nightshift.mjs --run      # execute the loop
 *
 * Optional:
 *   BOUNTY_ID=…            pin the bounty to claim
 *   WORK_FILE=./artifact   file to hash and submit
 *   WORK_URL=https://…     URL to fetch, hash, and submit
 *   SERVICE_ID=… SERVICE_TOOL=… SERVICE_PARAMS='{"city":"YYZ"}' SPEND_CENTS=2
 *   TRUST_BASE=https://entangleit.com/trust
 *   WATCH_MINUTES=30       keep polling the profile after the loop
 *
 * Safety: refuses to run without --run; never submits more than one bounty and
 * one paid service per invocation; leaves approval decisions to the human.
 */
const AGENTPAY_MCP = process.env.AGENTPAY_MCP ?? "https://entangleit.com/api/agentpay/mcp";
const TRUST_BASE = (process.env.TRUST_BASE ?? "https://entangleit.com/trust").replace(/\/$/, "");
const KEY = process.env.AGENTPAY_KEY ?? "";
const RUN = process.argv.includes("--run");

let rpcId = 0;
async function agentpay(tool, args = {}) {
  const res = await fetch(AGENTPAY_MCP, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(KEY ? { authorization: `Bearer ${KEY}` } : {}),
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: ++rpcId,
      method: "tools/call",
      params: { name: tool, arguments: args },
    }),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`${tool}: HTTP ${res.status}`);
  if (body?.error) throw new Error(`${tool}: ${body.error.message}`);
  const result = body?.result;
  if (result?.isError) throw new Error(`${tool}: ${(result.content?.[0]?.text ?? "error").slice(0, 300)}`);
  return result?.structuredContent ?? result;
}

async function trust(subject) {
  const res = await fetch(`${TRUST_BASE}/v1/profile/${encodeURIComponent(subject)}`);
  if (!res.ok) return null;
  return (await res.json()).profile;
}

function printTerms(label, profile) {
  if (!profile) {
    console.log(`${label}: no profile yet`);
    return;
  }
  const t = profile.terms ?? {};
  console.log(
    `${label}: ${profile.level} (score ${profile.score}) · approval ×${t.approvalMultiplier} · ` +
      `bond −${(t.bondDiscountBps ?? 0) / 100}% · discount ceiling ${(t.discountCeilingBps ?? 0) / 100}%`,
  );
}

function sha256Hex(bytes) {
  return crypto.subtle.digest("SHA-256", bytes).then((d) => [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join(""));
}

async function deliverableHash() {
  if (process.env.WORK_FILE) {
    const { readFile } = await import("node:fs/promises");
    return sha256Hex(await readFile(process.env.WORK_FILE));
  }
  if (process.env.WORK_URL) {
    const res = await fetch(process.env.WORK_URL);
    return sha256Hex(new Uint8Array(await res.arrayBuffer()));
  }
  return null;
}

function subjectFrom(balance) {
  if (process.env.TRUST_SUBJECT) return process.env.TRUST_SUBJECT;
  for (const key of ["walletId", "wallet_id", "wallet"]) {
    const value = balance?.[key];
    if (typeof value === "string" && value) return `wallet:${value}`;
  }
  return null;
}

if (!KEY.trim()) {
  console.error("AGENTPAY_KEY is required (agentpay agent key, agp_…).");
  process.exit(1);
}

console.log(`Nightshift ${RUN ? "(RUN)" : "(dry run — pass --run to execute)"}`);
const balance = await agentpay("get_balance");
console.log("agentpay:", JSON.stringify(balance).slice(0, 240));

const subject = subjectFrom(balance);
if (!subject) {
  console.error("Could not determine the wallet subject; set TRUST_SUBJECT=wallet:<id>.");
  process.exit(1);
}
printTerms("trust before", await trust(subject));

const bounties = await agentpay("list_bounties", { status: "open", limit: 20 });
const open = (bounties.bounties ?? bounties.items ?? bounties ?? []).filter((b) => b && b.id);
const pinned = process.env.BOUNTY_ID ? open.find((b) => b.id === process.env.BOUNTY_ID) : null;
const candidates = (pinned ? [pinned] : open)
  .filter((b) => b.status === "open" || b.status === undefined)
  .sort((a, b) => (a.amountSats ?? a.amount_sats ?? 0) - (b.amountSats ?? b.amount_sats ?? 0));
console.log(`open bounties: ${candidates.length}`);
for (const b of candidates.slice(0, 5)) {
  console.log(`  ${b.id}  ${b.amountSats ?? b.amount_sats ?? "?"} sats  ${b.title ?? ""}`);
}

if (!RUN) {
  console.log("\nPlan: claim the cheapest suitable bounty → submit sha256 → wait for payout → buy one x402 service.");
  console.log("Set BOUNTY_ID, WORK_FILE, SERVICE_ID, SERVICE_TOOL to pin the run. Nothing was changed.");
  process.exit(0);
}

const target = candidates[0];
if (!target) {
  console.error("No claimable bounty found. Seed one (hash acceptance) or pin BOUNTY_ID.");
  process.exit(1);
}
console.log(`claiming ${target.id} (${target.amountSats ?? target.amount_sats ?? "?"} sats)…`);
await agentpay("claim_bounty", { bountyId: target.id, ...(process.env.PAYOUT_ADDRESS ? { payoutAddress: process.env.PAYOUT_ADDRESS } : {}) });

const workHash = await deliverableHash();
if (!workHash) {
  console.error("WORK_FILE or WORK_URL is required so the submission is deterministic (sha256).");
  process.exit(1);
}
console.log(`submitting workHash=${workHash.slice(0, 16)}…`);
await agentpay("submit_work", { bountyId: target.id, workHash });

console.log("waiting for the board to settle (polling my_bounties)…");
let credited = false;
for (let i = 0; i < 40; i++) {
  const mine = await agentpay("my_bounties");
  const rows = mine.bounties ?? mine.items ?? [];
  const row = rows.find((b) => b.id === target.id || b.bountyId === target.id);
  if (row && ["paid", "settled", "credited"].includes(String(row.status ?? row.settleStatus ?? "").toLowerCase())) {
    credited = true;
    break;
  }
  await new Promise((r) => setTimeout(r, 15_000));
}
console.log(credited ? "paid into the wallet." : "not settled within the poll window; check my_bounties manually.");

if (process.env.SERVICE_ID && process.env.SERVICE_TOOL) {
  const params = process.env.SERVICE_PARAMS ? JSON.parse(process.env.SERVICE_PARAMS) : {};
  console.log(`buying ${process.env.SERVICE_ID}:${process.env.SERVICE_TOOL} for ${process.env.SPEND_CENTS ?? 2} cents…`);
  const receipt = await agentpay("pay_service", {
    serviceId: process.env.SERVICE_ID,
    tool: process.env.SERVICE_TOOL,
    params,
    amountCents: Number(process.env.SPEND_CENTS ?? 2),
  });
  console.log("paid:", JSON.stringify(receipt).slice(0, 240));
} else {
  console.log("SERVICE_ID/SERVICE_TOOL not set; skipping the x402 purchase.");
}

printTerms("trust after", await trust(subject));

const watchMinutes = Number(process.env.WATCH_MINUTES ?? 0);
if (watchMinutes > 0) {
  console.log(`watching the profile for ${watchMinutes} minutes…`);
  let last = "";
  const until = Date.now() + watchMinutes * 60_000;
  while (Date.now() < until) {
    const profile = await trust(subject);
    const line = profile ? `${profile.level} ${profile.score}` : "none";
    if (line !== last) {
      printTerms(new Date().toISOString(), profile);
      last = line;
    }
    await new Promise((r) => setTimeout(r, 60_000));
  }
}