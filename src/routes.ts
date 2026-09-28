/**
 * Route helpers for the Trust worker. Kept out of index.ts because Workers
 * modules may only export the handler: any other named export (like a string
 * constant) fails the runtime with "not of type function or ExportedHandler".
 */
export const MOUNT = "/trust";

/** Strip the mount prefix so routes read the same on workers.dev and the zone. */
export function routePath(pathname: string): string {
  if (pathname === MOUNT || pathname.startsWith(`${MOUNT}/`)) return pathname.slice(MOUNT.length) || "/";
  return pathname;
}

/** The bare mount path 308s to `${MOUNT}/`. */
export function mountRedirect(pathname: string): string | null {
  return pathname === MOUNT ? `${MOUNT}/` : null;
}