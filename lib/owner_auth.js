/**
 * Owner authentication for admin-only site intelligence routes.
 *
 * No existing owner/admin secret mechanism ships in this service, so one env
 * var is introduced: SITE_INTEL_TOKEN (alias OWNER_ADMIN_TOKEN). The secret is
 * NEVER committed. If the env var is unset the endpoint refuses with 503
 * not_configured rather than defaulting open — an unconfigured deploy is closed,
 * not public.
 *
 * Accepts either:
 *   Authorization: Bearer <token>
 *   ?token=<token>            (convenience for dashboard fetches)
 *
 * Comparison is constant-time to avoid leaking the token via timing.
 */

import crypto from 'crypto';

export function getConfiguredToken() {
  return process.env.SITE_INTEL_TOKEN || process.env.OWNER_ADMIN_TOKEN || null;
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * @returns {{ok:true, presented:string} | {ok:false, status:number, code:string, message:string}}
 */
export function checkOwnerAuth(req) {
  const configured = getConfiguredToken();
  if (!configured) {
    return {
      ok: false,
      status: 503,
      code: 'not_configured',
      message: 'Owner intelligence endpoint is not configured. Set SITE_INTEL_TOKEN in the environment.',
    };
  }
  const authHeader = req.headers?.authorization || '';
  let presented = null;
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  if (m) presented = m[1].trim();
  if (!presented && req.query && typeof req.query.token === 'string') presented = req.query.token;

  if (!presented) {
    return { ok: false, status: 401, code: 'unauthorized', message: 'Missing owner token. Provide Authorization: Bearer <token> or ?token=.' };
  }
  if (!safeEqual(presented, configured)) {
    return { ok: false, status: 401, code: 'unauthorized', message: 'Invalid owner token.' };
  }
  return { ok: true, presented };
}
