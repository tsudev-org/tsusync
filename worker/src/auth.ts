import { createMiddleware } from 'hono/factory';
import { EmbeddedJWK, calculateJwkThumbprint, createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet } from 'jose';

import { INSTALLATION_RE, namespaces } from './config';
import { b64url, hex, sha256 } from './crypto';
import type { AppEnv, Caller, Env } from './env';
import { ApiError, badRequest, unauthorized } from './errors';

/**
 * Xác thực = JWS quyền lợi do tsudev.com ký (PRODUCT_POLICY 7.4), app lấy qua `GET /api/me/entitlements` rồi gửi
 * `Authorization: Bearer <jws>`. JWS chứng minh `sub` + sản phẩm (`aud`) + `pro_until`; máy chủ KHÔNG tin cờ nào
 * khác từ app (N4). Quy tắc kiểm trùng với `EntitlementVerifier` của tsudev_ui:
 * - chỉ `alg` = ES256, header `typ` = `tsu-ent+jwt`, có `kid`; không dùng khoá nhúng (`jwk`/`jku`/`x5u`/`x5c`);
 * - khoá từ JWKS lấy qua discovery của `OIDC_ISSUER` (`issuer` khớp, `jwks_uri` https cùng máy chủ);
 * - `iss`, `aud` ∈ NAMESPACES, `exp` (không nới), `iat` ≤ bây giờ + 2 phút, `exp` ≤ `iat` + 7 ngày.
 * Thêm riêng cho TsuDEV Sync (ADR-0002):
 * - JWS phải TƯƠI: `iat` ≥ bây giờ - 24 giờ (giảm cửa sổ dùng lại JWS bị lộ từ 7 ngày xuống 24 giờ) ⇒ 401 `stale`.
 * - JWS có `cnf.jkt` (gắn khoá thiết bị) ⇒ bắt buộc `Authorization: DPoP <jws>` + header `DPoP` (RFC 9449).
 *   `DPOP_REQUIRED = "on"` ⇒ mọi JWS phải gắn khoá.
 */

export const JWS_TYPE = 'tsu-ent+jwt';
const MAX_LIFETIME_S = 7 * 24 * 3600;
const CLOCK_SKEW_S = 120;
const MAX_JWS_LEN = 4096;
const DISCOVERY_TTL = 3600 * 1000;
const JWKS_TTL = 3600 * 1000;
const JWKS_MIN_REFRESH = 60 * 1000;
const VERIFIED_MAX = 1000;
/** Tuổi tối đa của JWS (theo `iat`) mà TsuDEV Sync nhận - khớp "máy chủ sản phẩm đệm ≤ 24 giờ" (PRODUCT_POLICY 7.4). */
export const MAX_JWS_AGE_S = 24 * 3600;
const DPOP_WINDOW_S = 60;
const JKT_RE = /^[A-Za-z0-9_-]{43}$/;

let discoveryCache: { issuer: string; jwksUri: string; at: number } | null = null;
let jwksCache: { uri: string; keys: JSONWebKeySet; at: number } | null = null;
/** JWS đã kiểm (theo chính chuỗi JWS) - đỡ CPU trong giới hạn 10 ms/yêu cầu của gói Free. */
const verified = new Map<string, Caller & { exp: number }>();
/** `jti` của bằng chứng DPoP đã dùng (chống phát lại trong cửa sổ ±60 giây, theo isolate). */
const dpopSeen = new Map<string, number>();

/** Chỉ dùng trong test. */
export function resetAuthCaches() {
  discoveryCache = null;
  jwksCache = null;
  verified.clear();
  dpopSeen.clear();
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
  if (hit && hit.exp * 1000 > now && hit.iat >= now / 1000 - MAX_JWS_AGE_S) {
    return { ns: hit.ns, sub: hit.sub, jkt: hit.jkt, subKey: hit.subKey, proUntil: hit.proUntil, iat: hit.iat };
  }
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
  if (iat < now / 1000 - MAX_JWS_AGE_S) throw unauthorized('stale');
  const cnf = payload.cnf as { jkt?: unknown } | undefined;
  let jkt: string | null = null;
  if (cnf !== undefined) {
    if (typeof cnf !== 'object' || typeof cnf.jkt !== 'string' || !JKT_RE.test(cnf.jkt)) throw unauthorized();
    jkt = cnf.jkt;
  }

  const caller: Caller = {
    ns: aud,
    sub,
    jkt,
    subKey: hex(await sha256(`tsusync|${sub}`)),
    proUntil: Math.floor(proUntil) * 1000,
    iat: Math.floor(iat),
  };
  if (verified.size >= VERIFIED_MAX) verified.clear();
  verified.set(jws, { ...caller, exp });
  return caller;
}

/**
 * Kiểm bằng chứng DPoP (RFC 9449 mục 4.3): `typ` = `dpop+jwt`, ES256, khoá công khai P-256 trong header khớp `jkt`,
 * `htm`/`htu` khớp yêu cầu (bỏ query), `iat` trong ±60 giây, `jti` chưa dùng, `ath` = base64url(SHA-256(JWS)).
 */
export async function verifyDpop(proof: string | undefined, jkt: string, method: string, url: string, jws: string, now = Date.now()) {
  if (!proof || proof.length > 2048) throw unauthorized('invalid_dpop_proof');
  let payload: Record<string, unknown>;
  let jwk: Record<string, unknown>;
  try {
    const r = await jwtVerify(proof, EmbeddedJWK, { typ: 'dpop+jwt', algorithms: ['ES256'], currentDate: new Date(now) });
    payload = r.payload;
    jwk = (r.protectedHeader.jwk ?? {});
  } catch {
    throw unauthorized('invalid_dpop_proof');
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || 'd' in jwk) throw unauthorized('invalid_dpop_proof');
  if ((await calculateJwkThumbprint({ kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string }, 'sha256')) !== jkt) {
    throw unauthorized('invalid_dpop_proof');
  }
  const { htm, htu, iat, jti, ath } = payload;
  const target = new URL(url);
  let claimed: URL;
  try {
    claimed = new URL(typeof htu === 'string' ? htu : '');
  } catch {
    throw unauthorized('invalid_dpop_proof');
  }
  if (htm !== method || claimed.origin + claimed.pathname !== target.origin + target.pathname) throw unauthorized('invalid_dpop_proof');
  if (typeof iat !== 'number' || Math.abs(iat - now / 1000) > DPOP_WINDOW_S) throw unauthorized('invalid_dpop_proof');
  if (typeof jti !== 'string' || jti.length < 8 || jti.length > 64) throw unauthorized('invalid_dpop_proof');
  if (ath !== b64url(await sha256(jws))) throw unauthorized('invalid_dpop_proof');
  for (const [k, exp] of dpopSeen) if (exp < now) dpopSeen.delete(k);
  const key = `${jkt}:${jti}`;
  if (dpopSeen.has(key)) throw unauthorized('invalid_dpop_proof');
  if (dpopSeen.size >= VERIFIED_MAX) dpopSeen.clear();
  dpopSeen.set(key, now + 2 * DPOP_WINDOW_S * 1000);
}

/**
 * Middleware: bắt buộc JWS quyền lợi hợp lệ (`Authorization: Bearer <jws>`, hoặc `DPoP <jws>` khi JWS gắn khoá);
 * `X-Tsu-Installation` nếu có phải đúng định dạng (không lưu).
 */
export const requireCaller = createMiddleware<AppEnv>(async (c, next) => {
  const h = c.req.header('Authorization') ?? '';
  const m = /^(Bearer|DPoP) ([A-Za-z0-9_.-]+)$/.exec(h);
  if (!m?.[2]) throw unauthorized();
  const scheme = m[1];
  const jws = m[2];
  const inst = c.req.header('X-Tsu-Installation');
  if (inst !== undefined && !INSTALLATION_RE.test(inst)) throw badRequest('Mã cài đặt không hợp lệ.');
  const caller = await verifyEntitlement(c.env, jws);
  if (caller.jkt) {
    if (scheme !== 'DPoP') throw unauthorized('invalid_dpop_proof');
    await verifyDpop(c.req.header('DPoP'), caller.jkt, c.req.method, c.req.url, jws);
  } else if (c.env.DPOP_REQUIRED === 'on' || scheme === 'DPoP') {
    throw unauthorized('dpop_required');
  }
  c.set('caller', caller);
  await next();
});
