# EntangleIT Trust

Trust that changes terms. One worker that merges verified **spend**
([agentpay](https://entangleit.com/agentpay/)) and verified **work**
([BSVBounties](https://entangleit.com/bsvbounties/)) into a signed profile with
a level and the terms it unlocks:

| Level | Requires | Approval | Bond discount | Discount ceiling |
| --- | --- | --- | --- | --- |
| `new` | — | ×1 | 0% | 0% |
| `building` | one verified axis | ×1 | 0% | 0% |
| `proven` | spend + work verified | ×2 | 50% | 1% |
| `trusted` | volume, counterparties, 30d | ×3 | 100% | 2.5% |
| `elite` | volume, counterparties, 90d | ×4 | 100% | 5% |

Deterministic, ratcheted (one step up per 7 days, drops immediately), fail
closed. A Jev gray-zone band is advisory only — it can step terms down one
level, never grant eligibility.

Live: <https://entangleit.com/trust> · docs at `/trust/docs`.

## Layout

| Path | Purpose |
| --- | --- |
| `src/core.ts` | Canonical JSON, ES256 sign/verify, thresholds — the single copy that used to live in three repos |
| `src/score.ts` | Axes → level → terms, ratchet, score, confidence (pure) |
| `src/ingest.ts` | Bindings closure, attestation verification, axis extraction |
| `src/source.ts` | Reconcile: spend snapshots from the shared `entangleit` D1, reputation from BSVBounties |
| `src/store.ts` | D1 in production, in-memory in tests |
| `src/mcp.ts` | MCP tools: trust_profile, trust_terms, trust_verify, trust_bind, trust_leaderboard, billing, status |
| `src/x402.ts` | x402 v2 exact × bsv:mainnet seller helpers (shared with the other connectors) |
| `src/index.ts` | Worker: routes, paid `/profile`, bindings, ingest, reconcile, MCP, billing |
| `schema.sql` | `tr_*` tables in the shared `entangleit` D1 (additive) |
| `test/` | 41 tests: core crypto/gates, scoring, ingestion, MCP, worker surface, x402 |
| `scripts/acceptance.mjs` | Live acceptance against the deployed worker |
| `scripts/nightshift.mjs` | The demo worker: claim → submit → get paid → buy → watch trust move |
| `docs/INTEGRATION.md` | How agentpay, BSVBounties, x402-gateway, and bsvOS consume terms |

## Develop

```bash
npm install
npm test          # 41 tests, no network
npm run typecheck
npx wrangler dev  # in-memory store without D1
```

## Deploy

```bash
npm run deploy   # applies schema.sql to the shared entangleit D1, then deploys
npx wrangler secret put TRUST_KEY_JWK        # private P-256 JWK that signs profiles
npx wrangler secret put TRUST_INGEST_SECRET  # x-trust-internal for ingest/reconcile
npx wrangler secret put TRUST_ADMIN_TOKEN    # optional: operator token for acceptance runs
npx wrangler secret put ORACLE_GATEWAY_KEY   # optional: free gray-zone Jev band via decision-oracle
npx wrangler secret put STRIPE_SECRET_KEY    # optional billing
npx wrangler secret put STRIPE_WEBHOOK_SECRET
```

Generate a signing key:

```bash
node --input-type=module -e '
const kp = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
console.log(JSON.stringify(await crypto.subtle.exportKey("jwk", kp.privateKey)));'
```

## Signals (how profiles fill up)

1. **Reconcile** (no integration needed): reads aggregate spend from
   `ap_receipts` / `ap_ledger` / `ap_bounty_links` in the shared D1, fetches
   BSVBounties reputation, and binds wallets to bounty accounts automatically
   from the existing bridge. Run it every 15 minutes:
   `.github/workflows/reconcile.yml` calls `POST /v1/reconcile` with the
   internal secret.
2. **Signed push** (upgrade path): `POST /v1/ingest` accepts observations,
   signed agentpay attestations, and reputation snapshots from the products
   themselves.
3. **Self-serve bindings**: `GET /v1/bind/challenge` → sign
   `bind:<key>:<other>:<nonce>` → `POST /v1/bind`. Wallet bindings also
   require a signed agentpay attestation whose `sub` equals the key subject.

Nothing but `tr_*` is ever written. On-chain, marketplace, and account data
stay owned by their products; trust only reads and signs verdicts.

## Verifying a profile offline

1. `GET /trust/v1/key` → `publicJwk`.
2. Canonical JSON: object keys sorted, no whitespace (`stableStringify`).
3. Verify ES256 (ECDSA P-256 / SHA-256, raw P1363, base64url) over `profile`.
4. Check `expiresAt` and that `profile.sub` is the identity you asked about.

Any verification problem means full price and a human approval — never guessed
trust.