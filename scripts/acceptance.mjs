/**
 * Live acceptance for EntangleIT Trust.
 *
 *   TRUST_BASE=https://entangleit.com/trust node scripts/acceptance.mjs
 *   TRUST_BASE=http://localhost:8787 TRUST_SUBJECT=account:42 node scripts/acceptance.mjs
 *
 * Checks: health, public key, signed profile round trip (verify + tamper),
 * free profile read, badge, MCP initialize/tools list, and the paid challenge.
 * Exits non-zero on the first failure.
 */
const BASE = (process.env.TRUST_BASE ?? "https://entangleit.com/trust").replace(/\/$/, "");
const SUBJECT = process.env.TRUST_SUBJECT ?? "account:1";

let failures = 0;
function check(name, ok, detail = "") {
  const mark = ok ? "PASS" : "FAIL";
  console.log(`${mark} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures += 1;
}

async function get(path) {
  const res = await fetch(`${BASE}${path}`);
  return { res, body: await res.json().catch(() => null) };
}

async function post(path, body, headers = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { res, body: await res.json().catch(() => null) };
}

const health = await get("/health");
check("health", health.res.ok && health.body?.ok === true, `v${health.body?.version}`);

const key = await get("/v1/key");
check("public key", key.res.ok && key.body?.alg === "ES256", key.body?.keyId);
if (!key.body?.publicJwk) {
  console.error("no public key; cannot verify profiles");
  process.exit(1);
}

const profile = await get(`/v1/profile/${encodeURIComponent(SUBJECT)}`);
check("profile", profile.res.ok && profile.body?.profile?.sub === SUBJECT, `level=${profile.body?.profile?.level}`);
const signed = profile.body;

if (signed?.profile && signed?.signature) {
  const pub = await crypto.subtle.importKey("jwk", key.body.publicJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const canonical = (value) => {
    if (value === null || value === undefined) return "null";
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
    if (typeof value === "object") {
      return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
    }
    return JSON.stringify(value);
  };
  const b64 = (s) => {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice(0, (4 - (s.length % 4)) % 4));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  };
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pub,
    b64(signed.signature),
    new TextEncoder().encode(canonical(signed.profile)),
  );
  check("signature verifies", ok === true);
  const tampered = { ...signed.profile, level: "elite" };
  const bad = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pub,
    b64(signed.signature),
    new TextEncoder().encode(canonical(tampered)),
  );
  check("tampered profile rejected", bad === false);
  const verify = await post("/v1/verify", { profile: signed.profile, signature: signed.signature });
  check("verify endpoint", verify.body?.valid === true);
}

const badge = await fetch(`${BASE}/badge/${encodeURIComponent(SUBJECT)}.svg`);
check("badge", badge.ok && (badge.headers.get("content-type") ?? "").includes("svg"));

const mcp = await post("/mcp", { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
check("mcp initialize", mcp.body?.result?.serverInfo?.name === "entangleit-trust");

const tools = await post("/mcp", { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
const names = tools.body?.result?.tools?.map((t) => t.name) ?? [];
check("mcp tools", names.includes("trust_profile") && names.includes("trust_terms"), names.join(","));

const paid = await post("/profile", { subject: SUBJECT });
check("paid challenge", paid.res.status === 402, `status=${paid.res.status}`);

console.log(failures === 0 ? "\nAll acceptance checks passed." : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);