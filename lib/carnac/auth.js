/**
 * Carnac protected-route authentication and tenant resolution.
 *
 * Public routes (health, policy, sandbox, public verification) take no auth.
 * Every other Carnac route requires a constant-time bearer token:
 *
 *   - Owner/admin — the existing owner secret (SITE_INTEL_TOKEN / OWNER_ADMIN_TOKEN,
 *     see lib/owner_auth.js). The owner may act across tenants; a request may name
 *     a tenant via X-Carnac-Tenant / body.tenant_id, otherwise it is unscoped.
 *   - Service caller — a per-tenant service token configured in CARNAC_SERVICE_TOKENS
 *     as a comma-separated list of "tenant_id:token" pairs. A valid token binds the
 *     caller to exactly one tenant; it can never act on another tenant's records.
 *
 * The sandbox is an isolated public tenant (SANDBOX_TENANT) that never enters the
 * durable production ledger.
 *
 * Existence is never leaked: an unauthenticated caller is rejected (401/503)
 * before any record lookup, and a caller scoped to tenant A who asks for a
 * tenant-B record receives the same 404 as a genuinely missing record.
 */

import crypto from 'crypto';
import { checkOwnerAuth, getConfiguredToken } from '../owner_auth.js';

export const SANDBOX_TENANT = 'public-sandbox';

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** Parse CARNAC_SERVICE_TOKENS ("tenant:token,tenant2:token2") at call time. */
function serviceTokens() {
  const raw = process.env.CARNAC_SERVICE_TOKENS || '';
  const pairs = [];
  for (const part of raw.split(',')) {
    const s = part.trim();
    if (!s) continue;
    const idx = s.indexOf(':');
    if (idx <= 0) continue;
    const tenant_id = s.slice(0, idx).trim();
    const token = s.slice(idx + 1).trim();
    if (tenant_id && token) pairs.push({ tenant_id, token });
  }
  return pairs;
}

function bearer(req) {
  const h = req.headers?.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function requestedTenant(req) {
  const hdr = req.headers?.['x-carnac-tenant'];
  if (typeof hdr === 'string' && hdr.trim()) return hdr.trim();
  const b = req.body && typeof req.body.tenant_id === 'string' ? req.body.tenant_id.trim() : '';
  return b || null;
}

/**
 * Authenticate a protected Carnac request and resolve tenant scope.
 *
 * @param {object} req express request
 * @param {{requireTenant?:boolean}} [opts] requireTenant: the operation must be
 *   bound to a concrete tenant (owner must name one; service is inherently bound).
 * @returns {{ok:true, owner:boolean, tenant_id:string|null, actor:string}
 *          | {ok:false, status:number, code:string, message:string}}
 */
export function authenticateCarnac(req, { requireTenant = false } = {}) {
  const presented = bearer(req);
  if (!presented) {
    return { ok: false, status: 401, code: 'unauthorized', message: 'Missing bearer token.' };
  }

  // Owner/admin path — cross-tenant. Reuse the existing constant-time check.
  const ownerToken = getConfiguredToken();
  if (ownerToken) {
    const owner = checkOwnerAuth(req);
    if (owner.ok) {
      const tenant_id = requestedTenant(req);
      if (requireTenant && !tenant_id) {
        return { ok: false, status: 400, code: 'tenant_required', message: 'Owner must name a tenant via X-Carnac-Tenant or tenant_id for this operation.' };
      }
      return { ok: true, owner: true, tenant_id: tenant_id || null, actor: 'owner' };
    }
  }

  // Service-caller path — bound to exactly one tenant.
  for (const { tenant_id, token } of serviceTokens()) {
    if (safeEqual(presented, token)) {
      return { ok: true, owner: false, tenant_id, actor: `service:${tenant_id}` };
    }
  }

  return { ok: false, status: 401, code: 'unauthorized', message: 'Invalid bearer token.' };
}

/**
 * Decide whether an authenticated caller may access a record belonging to
 * ownerTenant. Owner may cross tenants; a service caller is confined to its own.
 */
export function tenantScopeAllows(auth, recordTenant) {
  if (!auth || !auth.ok) return false;
  if (auth.owner) {
    // If the owner named a tenant, confine to it; otherwise unscoped (all).
    return auth.tenant_id ? auth.tenant_id === recordTenant : true;
  }
  return auth.tenant_id === recordTenant;
}

/** True when any protected-route auth is configured (owner or service tokens). */
export function carnacAuthConfigured() {
  return Boolean(getConfiguredToken()) || serviceTokens().length > 0;
}
