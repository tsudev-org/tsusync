import { SignJWT, importJWK, type CryptoKey as JoseKey, type JWK } from 'jose';

import { randomToken } from './crypto';
import type { Env } from './env';

/**
 * Kênh trạng thái quyền lợi của tsudev.com (PRODUCT_POLICY 7.4, từ v4.0.0):
 * `POST {ENTITLEMENTS_STATUS_URL}` + `Authorization: Bearer <client assertion>` (private_key_jwt, RFC 7523),
 * thân `{"client_id": "<ns>", "subs": ["<sub>", ...]}` (≤ 100). tsudev.com trả trạng thái cho mọi `sub` ĐÃ TỪNG cấp
 * quyền cho `client_id` đó (không phụ thuộc grant OIDC 30 ngày) - đúng ca "gia hạn trên web mà không mở app".
 * Phản hồi: `{"results": {"<sub>": {"status": "ok", "pro_until": <giây>} | {"status": "deleted"} | {"status": "unknown_subject"}}}`.
 */
export type SubjectStatus = { status: 'ok'; proUntil: number } | { status: 'deleted' } | { status: 'unknown_subject' };

export const STATUS_MAX_SUBS = 100;
let signing: { raw: string; key: JoseKey | Uint8Array; kid?: string } | null = null;

export const rpConfigured = (env: Env) => !!(env.RP_PRIVATE_JWK && env.ENTITLEMENTS_STATUS_URL && env.RP_CLIENT_ID);

async function clientAssertion(env: Env): Promise<string> {
  const raw = env.RP_PRIVATE_JWK ?? '';
  if (signing?.raw !== raw) {
    const jwk = JSON.parse(raw) as JWK;
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d) throw new Error('rp_key');
    signing = { raw, key: await importJWK(jwk, 'ES256'), kid: jwk.kid };
  }
  return new SignJWT({})
    .setProtectedHeader(signing.kid ? { alg: 'ES256', typ: 'JWT', kid: signing.kid } : { alg: 'ES256', typ: 'JWT' })
    .setIssuer(env.RP_CLIENT_ID)
    .setSubject(env.RP_CLIENT_ID)
    .setAudience(env.ENTITLEMENTS_STATUS_URL)
    .setIssuedAt()
    .setExpirationTime('120s')
    .setJti(randomToken(24))
    .sign(signing.key);
}

/** Hỏi trạng thái Pro hiện tại. Lỗi mạng/HTTP/khung sai ⇒ ném lỗi (người gọi KHÔNG được xoá khi lỗi). */
export async function fetchSubjectStatus(env: Env, ns: string, subs: string[]): Promise<Map<string, SubjectStatus>> {
  const res = await fetch(env.ENTITLEMENTS_STATUS_URL, {
    method: 'POST',
    redirect: 'error',
    headers: { Authorization: `Bearer ${await clientAssertion(env)}`, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ client_id: ns, subs: subs.slice(0, STATUS_MAX_SUBS) }),
  });
  if (!res.ok) throw new Error(`status_${res.status}`);
  const body = await res.json<{ results?: unknown }>();
  if (!body.results || typeof body.results !== 'object') throw new Error('status_body');
  const out = new Map<string, SubjectStatus>();
  for (const sub of subs) {
    const r = (body.results as Record<string, { status?: unknown; pro_until?: unknown } | undefined>)[sub];
    if (r?.status === 'ok' && typeof r.pro_until === 'number' && Number.isFinite(r.pro_until) && r.pro_until >= 0) {
      out.set(sub, { status: 'ok', proUntil: Math.floor(r.pro_until) * 1000 });
    } else if (r?.status === 'deleted') {
      out.set(sub, { status: 'deleted' });
    } else {
      out.set(sub, { status: 'unknown_subject' });
    }
  }
  return out;
}
