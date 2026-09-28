# Wiring consumers to Trust

Trust already works without touching the products: `POST /v1/reconcile` reads
aggregate spend from the shared `entangleit` D1, pulls BSVBounties reputation,
and auto-binds wallets to bounty accounts from `ap_bounty_links`. The edits
below upgrade consumers from their **vendored gates** to **signed terms**, and
should land one service at a time, each behind `off | log | enforce`.

Common rules:

- Verify the profile offline with `/trust/v1/key` (ES256 over canonical JSON),
  or call `POST /trust/v1/verify`. Fail closed: any problem means the old,
  stricter path.
- Consumers always take `min(their own cap, terms)` — trust loosens, never
  uncaps.
- Never let a Trust outage block money: fall back to the existing behavior.
- Internal reads use the service binding (or `TRUST_URL`) plus the
  `x-trust-internal` shared secret; bindings bypass the public daily limit.

## agentpay (`worker/src/trust.ts`)

Current: fetches BSVBounties reputation and multiplies the approval threshold
by 2. Replace the reputation input with the signed profile for
`wallet:<walletId>`:

```ts
// wrangler.toml: [[services]] binding = "TRUST" service = "entangleit-trust"
const profile = await fetchTrustProfile(env, `wallet:${walletId}`);   // cached 5 min
if (profile?.terms?.approvalMultiplier) {
  effectiveApproval = applyMultiplier(baseApproval, profile.terms.approvalMultiplier);
}
```

- Keep `TRUST_GATE_PAY = off | log | enforce`; in `log` mode compute and record
  the delta without using it.
- Add `TRUST_URL` fallback for local dev; skip silently when unset.
- Approval threshold only. Daily limits and sub-agent budgets stay untouched in
  v1.
- Optional: push `payment_settled` observations on every settled `pay_service`
  with `POST /trust/v1/ingest` for near-real-time growth (reconcile already
  covers the daily snapshot).

## BSVBounties (`apps/api/src/trust.ts`, `packages/shared/src/trust.ts`)

Current: verifies agentpay attestations and discounts worker bonds 50% until
the wallet↔account binding lands. Replace with the profile for
`account:<workerAccount>`:

```ts
const profile = await fetchTrustProfile(env, `account:${workerAccount}`);
const discountBps = profile?.terms?.bondDiscountBps ?? 0;
const bond = applyBondDiscount(baseBond, discountBps);
```

- `proven` (50%) and `trusted`/`elite` (100%) come from the scored profile, and
  now include spend history plus completed work — no more "until binding lands".
- Keep `TRUST_GATE_CLAIM = off | log | enforce`; the attestation path stays as
  the fallback in log mode.
- Reputation is already merged by reconcile. Push `bounty_paid` and
  `dispute_lost` observations on settle for immediacy and for the ratchet's
  downgrade path.

## x402 Gateway (`src/trust.ts`)

Current: buyers send `X-Trust-Attestation`, the gateway verifies metrics and
applies the route's `trustDiscountBps`. Add the profile as the preferred path:

- New header `X-Trust-Profile: b64({ profile, signature })`. Verify offline
  with `/trust/v1/key`, check `expiresAt`, and require that the subject binds to
  the verified payer (same `sub` discipline as the attestation path).
- Effective discount = `min(route.trustDiscountBps, profile.terms.discountCeilingBps)`.
  A seller can never be forced to discount more than its route allows.
- Keep `X-Trust-Attestation` as the fallback for anonymous buyers and for
  older agents. Add `TRUST_MODE = off | log | enforce`.

## bsvOS (`src/mcp.ts`)

Add a `trust_terms` MCP tool that fetches
`GET /trust/v1/profile/key:<identityKey-derived subject>`.

- The Jev advisor uses `terms.approvalMultiplier` only to widen its `--auto`
  band inside the origin's existing cap or sub-wallet budget.
- Never removes the policy gate; never adds an open send. Denials still relay
  to the human verbatim.

## Rollout order

1. Deploy Trust, set secrets, run `scripts/acceptance.mjs`.
2. Enable `.github/workflows/reconcile.yml` (needs the
   `TRUST_INGEST_SECRET` repository secret).
3. Watch `log` mode deltas for ~3 days across agentpay and bounties: the deltas
   must equal the pure calculator in `src/score.ts`.
4. Flip `enforce` for BSVBounties first (bond discounts are the lowest-risk
   surface), then agentpay approvals, then gateway discounts.
5. Publish the Nightshift profile page as the reference loop.