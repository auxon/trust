/**
 * Public badge and profile page. The badge is a plain SVG so it can be
 * embedded anywhere; the page is a readable summary that links to the signed
 * JSON. Neither ever states anything the signature does not.
 */
import type { TrustLevel, TrustProfile } from "./core.ts";

export const LEVEL_COLORS: Record<TrustLevel, string> = {
  new: "#64748b",
  building: "#0ea5e9",
  proven: "#22c55e",
  trusted: "#a855f7",
  elite: "#f59e0b",
};

function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function badgeSvg(level: TrustLevel, score: number): string {
  const color = LEVEL_COLORS[level] ?? LEVEL_COLORS.new;
  const label = `trust ${level} ${score}`;
  const width = Math.max(120, 56 + label.length * 7);
  const labelX = 52;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="${escapeXml(label)}">` +
    `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>` +
    `<rect width="100%" height="20" rx="3" fill="#0b0e13"/>` +
    `<rect x="44" width="${width - 44}" height="20" rx="3" fill="${color}" fill-opacity="0.22"/>` +
    `<rect width="44" height="20" rx="3" fill="#1f2733"/>` +
    `<rect x="44" width="4" height="20" fill="${color}"/>` +
    `<g fill="#e8ecf2" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="22" y="14">trust</text>` +
    `<text x="${labelX + (width - labelX) / 2}" y="14" fill="${color}">${escapeXml(`${level} ${score}`)}</text>` +
    `</g></svg>`
  );
}

export function profilePage(base: string, subject: string, profile: TrustProfile, signature: string): string {
  const color = LEVEL_COLORS[profile.level] ?? LEVEL_COLORS.new;
  const meter = Math.max(0, Math.min(100, Math.round(profile.score / 10)));
  const reasons = profile.reasons.map((r) => `<li>${escapeXml(r)}</li>`).join("");
  return (
    `<!doctype html><html><head><meta charset="utf-8"><title>${escapeXml(subject)} — EntangleIT Trust</title>` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<style>body{background:#0b0e13;color:#e8ecf2;font:16px/1.6 system-ui;margin:0}` +
    `main{max-width:46rem;margin:0 auto;padding:3rem 1.25rem}` +
    `h1{font-size:1.5rem;word-break:break-all}.level{color:${color};font-weight:700;text-transform:uppercase;letter-spacing:.08em}` +
    `.bar{height:10px;background:#1f2733;border-radius:5px;overflow:hidden;margin:1rem 0}.bar>i{display:block;height:100%;width:${meter}%;background:${color}}` +
    `dl{display:grid;grid-template-columns:auto 1fr;gap:.25rem 1rem;margin:1.5rem 0}` +
    `dt{color:#93a1b3}dd{margin:0}code{background:#151b24;padding:.15rem .35rem;border-radius:4px;word-break:break-all}` +
    `footer{color:#93a1b3;margin-top:2rem;font-size:.9rem}a{color:#2dd4bf}</style></head><body><main>` +
    `<p><a href="${escapeXml(base)}/">EntangleIT Trust</a></p>` +
    `<h1>${escapeXml(subject)}</h1>` +
    `<p class="level">${escapeXml(profile.level)} · score ${profile.score} · confidence ${profile.confidence}</p>` +
    `<div class="bar"><i></i></div>` +
    `<dl>` +
    `<dt>Issued</dt><dd>${escapeXml(profile.issuedAt)}</dd>` +
    `<dt>Expires</dt><dd>${escapeXml(profile.expiresAt)}</dd>` +
    `<dt>Terms</dt><dd>approval ×${profile.terms.approvalMultiplier} · bond −${profile.terms.bondDiscountBps / 100}% · discount ceiling ${profile.terms.discountCeilingBps / 100}%</dd>` +
    (profile.axes.spend
      ? `<dt>Spend</dt><dd>${profile.axes.spend.settledPayments} settled payments · ${profile.axes.spend.distinctServices} services · $${(profile.axes.spend.spentCents / 100).toFixed(2)}</dd>`
      : "") +
    (profile.axes.work
      ? `<dt>Work</dt><dd>reputation ${profile.axes.work.score}${profile.axes.work.tier ? ` (${profile.axes.work.tier})` : ""} · ${profile.axes.work.completed} completed · ${profile.axes.work.slashes} slashes</dd>`
      : "") +
    `</dl>` +
    `<h2>Why</h2><ul>${reasons}</ul>` +
    `<footer>Signed by <code>${escapeXml(profile.iss)}</code>. JSON: ` +
    `<a href="${escapeXml(base)}/v1/profile/${encodeURIComponent(subject)}">signed profile</a> · ` +
    `<a href="${escapeXml(base)}/badge/${encodeURIComponent(subject)}.svg">badge</a> · ` +
    `verify offline with the <a href="${escapeXml(base)}/v1/key">public key</a>.</footer>` +
    `</main></body></html>`
  );
}