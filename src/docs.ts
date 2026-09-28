/**
 * Landing and docs pages, served by the worker (matches the other EntangleIT
 * connectors: no separate frontend to keep in sync).
 */

function shell(title: string, body: string): string {
  return (
    `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<style>body{background:#0b0e13;color:#e8ecf2;font:16px/1.7 system-ui;margin:0}` +
    `main{max-width:52rem;margin:0 auto;padding:3rem 1.25rem}a{color:#2dd4bf}code,pre{background:#151b24;border-radius:6px}` +
    `code{padding:.15rem .35rem}pre{padding:1rem;overflow:auto}table{border-collapse:collapse;width:100%;margin:1rem 0}` +
    `th,td{text-align:left;border-bottom:1px solid #1f2733;padding:.45rem .5rem;vertical-align:top}` +
    `h2{margin-top:2rem}footer{color:#93a1b3;margin-top:3rem;font-size:.9rem}</style></head><body><main>${body}` +
    `<footer>EntangleIT Trust — part of the <a href="https://entangleit.com/">agent economy stack</a>.</footer></main></body></html>`
  );
}

export function renderLanding(base: string): string {
  return shell(
    "EntangleIT Trust — trust that changes terms",
    `<h1>EntangleIT Trust</h1>` +
      `<p>One signed profile that turns verified history into <strong>terms</strong>: skip a human approval, ` +
      `post a smaller bond, earn a seller discount. Trust is earned on the rails — spend, work, time — ` +
      `never bought and never decided by vibes.</p>` +
      `<pre>curl -s ${base}/v1/profile/account:1\n` +
      `# { profile: { level, score, terms, axes, … }, signature, keyId }</pre>` +
      `<p>Agents connect over MCP at <code>${base}/mcp</code>. Paid per-call lookups are x402 (5 sats, BSV); ` +
      `verification is free and offline with the <a href="${base}/v1/key">public key</a>.</p>` +
      `<p><a href="${base}/docs">Documentation</a> · <a href="${base}/v1/status">status</a></p>`,
  );
}

export function renderDocs(base: string): string {
  return shell(
    "EntangleIT Trust — documentation",
    `<h1>Documentation</h1>` +
      `<p>Trust answers one question for the rest of the stack: <em>what terms does this identity deserve?</em> ` +
      `It merges verified spend (agentpay attestations or the shared ledger) and verified work (BSVBounties ` +
      `reputation) into a signed profile with a level and a terms block.</p>` +
      `<h2>Levels and terms</h2>` +
      `<table><tr><th>Level</th><th>Requires</th><th>Approval</th><th>Bond discount</th><th>Discount ceiling</th></tr>` +
      `<tr><td>new</td><td>—</td><td>×1</td><td>0%</td><td>0%</td></tr>` +
      `<tr><td>building</td><td>one verified axis</td><td>×1</td><td>0%</td><td>0%</td></tr>` +
      `<tr><td>proven</td><td>spend + work verified</td><td>×2</td><td>50%</td><td>1%</td></tr>` +
      `<tr><td>trusted</td><td>volume, counterparties, 30d</td><td>×3</td><td>100%</td><td>2.5%</td></tr>` +
      `<tr><td>elite</td><td>volume, counterparties, 90d</td><td>×4</td><td>100%</td><td>5%</td></tr></table>` +
      `<p>Thresholds live in <code>core.ts</code> and are identical to the gates agentpay, BSVBounties, and the ` +
      `x402 Gateway already shipped. Trust climbs at most one level per ratchet window (default 7 days) and drops ` +
      `immediately when evidence drops. A Jev "hold" band can only step terms down one level; it never grants ` +
      `eligibility.</p>` +
      `<h2>HTTP surface</h2>` +
      `<table><tr><th>Route</th><th>Purpose</th></tr>` +
      `<tr><td><code>GET /v1/profile/:subject</code></td><td>Signed profile (free, IP rate-limited; internal secret bypasses)</td></tr>` +
      `<tr><td><code>POST /profile</code></td><td>x402 paid lookup (5 sats) for agents without accounts</td></tr>` +
      `<tr><td><code>POST /v1/verify</code></td><td>Verify a signed profile against this issuer's key</td></tr>` +
      `<tr><td><code>GET /v1/key</code></td><td>Public verification key</td></tr>` +
      `<tr><td><code>GET /v1/bind/challenge?key=</code>, <code>POST /v1/bind</code></td><td>Two-sided binding (signed challenge, optional attestation proof)</td></tr>` +
      `<tr><td><code>POST /v1/ingest</code></td><td>Internal: push observations, attestations, reputation (x-trust-internal)</td></tr>` +
      `<tr><td><code>POST /v1/reconcile</code></td><td>Internal: pull spend snapshots and reputations, auto-bind linked wallets</td></tr>` +
      `<tr><td><code>GET /p/:subject</code>, <code>GET /badge/:subject.svg</code></td><td>Human page and embeddable badge</td></tr>` +
      `<tr><td><code>POST /mcp</code></td><td>Remote MCP server (trust_profile, trust_terms, trust_verify, trust_bind, trust_leaderboard, billing, status)</td></tr></table>` +
      `<h2>Subjects</h2>` +
      `<p><code>wallet:&lt;id&gt;</code> (agentpay wallet), <code>account:&lt;n&gt;</code> (BSVBounties numbered account), ` +
      `<code>key:&lt;thumbprint&gt;</code> (P-256 key thumbprint). Bindings merge axes across subjects; a profile is ` +
      `issued for whichever subject you ask about.</p>` +
      `<h2>Verifying offline</h2>` +
      `<pre>1. GET ${base}/v1/key → publicJwk\n` +
      `2. Canonical JSON: sort object keys, no whitespace (stableStringify)\n` +
      `3. Verify ES256 (ECDSA P-256/SHA-256, raw P1363, base64url) over profile\n` +
      `4. Check expiresAt and that profile.sub is the identity you asked about</pre>` +
      `<p>Fail closed: any verification problem means full price and a human approval — never guessed trust.</p>`,
  );
}