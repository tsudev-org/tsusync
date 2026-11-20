import { createMiddleware } from 'hono/factory';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet } from 'jose';

import { INSTALLATION_RE, namespaces } from './config';
import { hex, sha256 } from './crypto';
import type { AppEnv, Caller, Env } from './env';
import { ApiError, badRequest, unauthorized } from './errors';

/**
 * Xác thực = JWS quyền lợi do tsudev.com ký (PRODUCT_POLICY 7.4), app lấy qua `GET /api/me/entitlements` rồi gửi
 * `Authorization: Bearer <jws>`. JWS chứng minh `sub` + sản phẩm (`aud`) + `pro_until`; máy chủ KHÔNG tin cờ nào
 * khác từ app (N4). Quy tắc kiểm trùng với `EntitlementVerifier` của tsudev_ui:
 * - chỉ `alg` = ES256, header `typ` = `tsu-ent+jwt`, có `kid`; không dùng khoá nhúng (`jwk`/`jku`/`x5u`/`x5c`);
 * - khoá từ JWKS lấy qua discovery của `OIDC_ISSUER` (`issuer` khớp, `jwks_uri` https cùng máy chủ);
 * - `iss`, `aud` ∈ NAMESPACES, `exp` (không nới), `iat` ≤ bây giờ + 2 phút, `exp` ≤ `iat` + 7 ngày.
 */

export const JWS_TYPE = 'tsu-ent+jwt';
const MAX_LIFETIME_S = 7 * 24 * 3600;
const CLOCK_SKEW_S = 120;
const MAX_JWS_LEN = 4096;
const DISCOVERY_TTL = 3600 * 1000;
const JWKS_TTL = 3600 * 1000;
const JWKS_MIN_REFRESH = 60 * 1000;
const VERIFIED_MAX = 1000;

let discoveryCache: { issuer: string; jwksUri: string; at: number } | null = null;
let jwksCache: { uri: string; keys: JSONWebKeySet; at: number } | null = null;
/** JWS đã kiểm (theo chính chuỗi JWS) - đỡ CPU trong giới hạn 10 ms/yêu cầu của gói Free. */
const verified = new Map<string, Caller & { exp: number }>();

/** Chỉ dùng trong test. */
export function resetAuthCaches() {
  discoveryCache = null;
  jwksCache = null;
  verified.clear();
}

async function getJson(url: string): Promise<unknown> {
  const res = await fetch(url, { headers: { Accept: 'application/json' }, redirect: 'error' });
  if (!res.ok) throw new Error(`idp_${res.status}`);
  return res.json();
}

async function jwksUri(env: Env): Promise<string> {
  const now = Date.now();
  if (discoveryCache?.issuer === env.OIDC_ISSUER && now - discoveryCache.at < DISCOVERY_TTL) return discoveryCache.jwksUri;
  const d = (await getJson(`${env.OIDC_ISSUER}/.well-known/openid-configuration`)) as { issuer?: unknown; jwks_uri?: unknown };
  if (d.issuer !== env.OIDC_ISSUER || typeof d.jwks_uri !== 'string') throw new Error('idp_discovery');
  const u = new URL(d.jwks_uri);
  if (u.protocol !== 'https:' || u.host !== new URL(env.OIDC_ISSUER).host) throw new Error('idp_jwks_uri');
  discoveryCache = { issuer: env.OIDC_ISSUER, jwksUri: d.jwks_uri, at: now };
  return d.jwks_uri;
}

async function jwks(env: Env, force: boolean): Promise<JSONWebKeySet> {
  const uri = await jwksUri(env);
  const now = Date.now();
  const cached = jwksCache?.uri === uri ? jwksCache : null;
  if (cached && now - cached.at < JWKS_TTL && (!force || now - cached.at < JWKS_MIN_REFRESH)) return cached.keys;
  const raw = (await getJson(uri)) as { keys?: unknown };
  if (!Array.isArray(raw.keys)) throw new Error('idp_jwks');
  // Chỉ giữ khoá EC P-256 dùng để ký - không bao giờ nhận khoá đối xứng hay RSA cho JWS quyền lợi.
  const keys = (raw.keys as Record<string, unknown>[]).filter(
    (k) => k.kty === 'EC' && k.crv === 'P-256' && typeof k.kid === 'string' && (k.use === undefined || k.use === 'sig') && !('d' in k),
  );
  const set = { keys };
  jwksCache = { uri, keys: set, at: now };
  return set;
}

const unavailable = () =>
  new ApiError(503, 'entitlements_unavailable', 'Chưa kiểm được quyền lợi TsuDEV. Dữ liệu vẫn an toàn trên máy, hãy thử lại sau.', undefined, {
    'Retry-After': '60',
  });

export async function verifyEntitlement(env: Env, jws: string, now = Date.now()): Promise<Caller> {
  const hit = verified.get(jws);
  if (hit && hit.exp * 1000 > now) return { ns: hit.ns, subKey: hit.subKey, proUntil: hit.proUntil, iat: hit.iat };
  if (hit) verified.delete(jws);

  if (jws.length > MAX_JWS_LEN) throw unauthorized();
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(jws);
  } catch {
    throw unauthorized();
  }
  if (header.alg !== 'ES256' || header.typ !== JWS_TYPE || typeof header.kid !== 'string') throw unauthorized();
  if ('jwk' in header || 'jku' in header || 'x5u' in header || 'x5c' in header || 'crit' in header) throw unauthorized();

  const allowed = namespaces(env);
  let payload: Record<string, unknown>;
  for (let attempt = 0; ; attempt++) {
    let keys: JSONWebKeySet;
    try {
      keys = await jwks(env, attempt > 0);
    } catch {
      throw unavailable();
    }
    try {
      const r = await jwtVerify(jws, createLocalJWKSet(keys), {
        algorithms: ['ES256'],
        typ: JWS_TYPE,
        issuer: env.OIDC_ISSUER,
        currentDate: new Date(now),
      });
      payload = r.payload;
      break;
    } catch (e) {
      // Khoá mới xoay vòng chưa có trong cache ⇒ tải lại JWKS đúng một lần (có giới hạn tần suất ở jwks()).
      if (attempt === 0 && e instanceof Error && 'code' in e && e.code === 'ERR_JWKS_NO_MATCHING_KEY') continue;
      throw unauthorized();
    }
  }

  const { sub, aud, iat, exp, pro_until: proUntil } = payload;
  if (typeof sub !== 'string' || sub.length === 0 || sub.length > 255) throw unauthorized();
  if (typeof aud !== 'string' || !allowed.has(aud)) throw unauthorized();
  if (typeof iat !== 'number' || typeof exp !== 'number' || !Number.isFinite(iat) || !Number.isFinite(exp)) throw unauthorized();
  if (exp <= iat || exp - iat > MAX_LIFETIME_S || iat > now / 1000 + CLOCK_SKEW_S || exp * 1000 <= now) throw unauthorized();
  if (typeof proUntil !== 'number' || !Number.isFinite(proUntil) || proUntil < 0) throw unauthorized();

  const caller: Caller = {
    ns: aud,
    subKey: hex(await sha256(`tsusync|${sub}`)),
    proUntil: Math.floor(proUntil) * 1000,
    iat: Math.floor(iat),
  };
  if (verified.size >= VERIFIED_MAX) verified.clear();
  verified.set(jws, { ...caller, exp });
  return caller;
}

/** Middleware: bắt buộc JWS quyền lợi hợp lệ; `X-Tsu-Installation` nếu có phải đúng định dạng (không lưu). */
export const requireCaller = createMiddleware<AppEnv>(async (c, next) => {
  const h = c.req.header('Authorization') ?? '';
  const m = /^Bearer ([A-Za-z0-9_.-]+)$/.exec(h);
  if (!m?.[1]) throw unauthorized();
  const inst = c.req.header('X-Tsu-Installation');
  if (inst !== undefined && !INSTALLATION_RE.test(inst)) throw badRequest('Mã cài đặt không hợp lệ.');
  c.set('caller', await verifyEntitlement(c.env, m[1]));
  await next();
});
