import { SignJWT } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';

import { DAY, ISSUER, call, json, jws, jwksFetches, makeKey, setJwksOverride, setupIdp } from './helpers';

beforeEach(setupIdp);

describe('sức khoẻ + header bảo mật', () => {
  it('health không cần xác thực, có no-store + nosniff', async () => {
    const res = await call('/v1/health');
    expect(res.status).toBe(200);
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('đường lạ ⇒ 404 JSON', async () => {
    const res = await call('/khong-co');
    expect(res.status).toBe(404);
    expect((await json(res)).error).toBe('not_found');
  });
});

describe('xác thực bằng JWS quyền lợi (PRODUCT_POLICY 7.4)', () => {
  it('thiếu Authorization ⇒ 401 invalid_token', async () => {
    const res = await call('/v1/account');
    expect(res.status).toBe(401);
    expect(res.headers.get('WWW-Authenticate')).toContain('invalid_token');
    expect((await json(res)).error).toBe('invalid_token');
  });

  it('JWS hợp lệ ⇒ 200, không gian tên = aud', async () => {
    const res = await call('/v1/account', { token: await jws() });
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(body.namespace).toBe('tsufiles');
    expect(body.pro).toBe(true);
    expect(body.quota).toEqual({ data_bytes: 0, data_limit: 100 * 1024 * 1024, file_bytes: 0, file_limit: 1024 * 1024 * 1024 });
  });

  const bad: [string, () => Promise<string>][] = [
    ['sai typ', () => jws({}, { typ: 'JWT' })],
    ['sai iss', () => jws({ iss: 'https://evil.test/oidc' })],
    ['aud không thuộc NAMESPACES', () => jws({ aud: 'qulythuchi' })],
    ['đã hết hạn', () => jws({ iat: Math.floor(Date.now() / 1000) - 8 * DAY, exp: Math.floor(Date.now() / 1000) - DAY })],
    ['exp > iat + 7 ngày', () => jws({ exp: Math.floor(Date.now() / 1000) + 8 * DAY })],
    ['iat ở tương lai quá 2 phút', () => jws({ iat: Math.floor(Date.now() / 1000) + 600, exp: Math.floor(Date.now() / 1000) + DAY })],
    ['khoá lạ cùng kid', async () => jws({}, { key: await makeKey('k1') })],
    ['chuỗi rác', () => Promise.resolve('abc.def.ghi')],
  ];
  for (const [name, make] of bad) {
    it(`${name} ⇒ 401`, async () => {
      const res = await call('/v1/account', { token: await make() });
      expect(res.status).toBe(401);
    });
  }

  it('alg HS256 (khoá đối xứng) ⇒ 401', async () => {
    const t = await new SignJWT({ pro_until: 9_999_999_999 })
      .setProtectedHeader({ alg: 'HS256', typ: 'tsu-ent+jwt', kid: 'k1' })
      .setIssuer(ISSUER)
      .setSubject('user-1')
      .setAudience('tsufiles')
      .setIssuedAt()
      .setExpirationTime('1d')
      .sign(new TextEncoder().encode('0123456789abcdef0123456789abcdef'));
    expect((await call('/v1/account', { token: t })).status).toBe(401);
  });

  it('kid mới (xoay khoá) ⇒ tải lại JWKS đúng một lần rồi nhận', async () => {
    const k2 = await makeKey('k2');
    expect((await call('/v1/account', { token: await jws() })).status).toBe(200);
    expect(jwksFetches).toBe(1);
    setJwksOverride([k2.jwk]);
    // Cache JWKS còn trẻ hơn 60 giây ⇒ chưa tải lại ⇒ 401, không dội tsudev.com.
    expect((await call('/v1/account', { token: await jws({ sub: 'u-rot' }, { key: k2 }) })).status).toBe(401);
    expect(jwksFetches).toBe(1);
  });

  it('tsudev.com không trả JWKS ⇒ 503 có Retry-After', async () => {
    setJwksOverride(null);
    const { vi } = await import('vitest');
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(new Response('down', { status: 502 })));
    const res = await call('/v1/account', { token: await jws({ sub: 'u-down' }) });
    expect(res.status).toBe(503);
    expect(res.headers.get('Retry-After')).toBe('60');
  });

  it('X-Tsu-Installation sai định dạng ⇒ 400', async () => {
    const res = await call('/v1/account', { token: await jws(), headers: { 'X-Tsu-Installation': 'ngan' } });
    expect(res.status).toBe(400);
  });
});
