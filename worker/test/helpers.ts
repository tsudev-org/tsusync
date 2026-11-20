import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, jwtVerify, importJWK, type CryptoKey as JoseKey, type JWK } from 'jose';
import { vi } from 'vitest';

import { resetAuthCaches } from '../src/auth';
import type { Env } from '../src/env';
import app from '../src/index';

export const ISSUER = 'https://idp.test/oidc';
export const DAY = 24 * 3600;

interface Keys {
  privateKey: JoseKey;
  jwk: JWK;
}

let keys: Keys | null = null;
export let jwksFetches = 0;
export let jwksOverride: JWK[] | null = null;
export const setJwksOverride = (k: JWK[] | null) => {
  jwksOverride = k;
};

export const STATUS_URL = 'https://idp.test/api/rp/entitlements/status';
/** Trả lời kênh trạng thái (mặc định: không ai biết). Ghi lại từng lượt gọi để test kiểm client assertion. */
export let statusResponder: (body: { client_id: string; subs: string[] }) => Response = () => Response.json({ results: {} });
export const statusCalls: { auth: string; body: { client_id: string; subs: string[] } }[] = [];
export const setStatusResponder = (fn: typeof statusResponder) => {
  statusResponder = fn;
};

let rpKeys: { privateJwk: string; publicJwk: JWK } | null = null;
/** Khoá RP giả của client `tsusync` (chỉ cho test). */
export async function rpKey() {
  if (!rpKeys) {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    rpKeys = { privateJwk: JSON.stringify({ ...(await exportJWK(privateKey)), kid: 'rp1' }), publicJwk: await exportJWK(publicKey) };
  }
  return rpKeys;
}

/** Kiểm client assertion như tsudev.com sẽ kiểm (RFC 7523). */
export async function verifyAssertion(auth: string) {
  const { publicJwk } = await rpKey();
  const token = auth.replace(/^Bearer /, '');
  const { payload } = await jwtVerify(token, await importJWK(publicJwk, 'ES256'), { audience: STATUS_URL, issuer: 'tsusync', subject: 'tsusync' });
  return payload;
}

export async function makeKey(kid: string): Promise<Keys> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, use: 'sig', alg: 'ES256' };
  return { privateKey, jwk };
}

export async function setupIdp() {
  keys ??= await makeKey('k1');
  resetAuthCaches();
  jwksFetches = 0;
  jwksOverride = null;
  statusCalls.length = 0;
  statusResponder = () => Response.json({ results: {} });
  vi.spyOn(globalThis, 'fetch').mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url === STATUS_URL) {
      const headers = new Headers(init?.headers);
      const body = JSON.parse(init?.body as string) as { client_id: string; subs: string[] };
      statusCalls.push({ auth: headers.get('Authorization') ?? '', body });
      return Promise.resolve(statusResponder(body));
    }
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return Promise.resolve(Response.json({ issuer: ISSUER, jwks_uri: 'https://idp.test/oidc/jwks' }));
    }
    if (url === 'https://idp.test/oidc/jwks') {
      jwksFetches++;
      return Promise.resolve(Response.json({ keys: jwksOverride ?? [keys?.jwk] }));
    }
    return Promise.resolve(new Response('not found', { status: 404 }));
  });
}

export interface Claims {
  sub?: string;
  aud?: string;
  iss?: string;
  iat?: number;
  exp?: number;
  pro_until?: number;
  cnf?: { jkt: string };
}

/** JWS quyền lợi giả lập. Mặc định: Pro còn 30 ngày, aud = tsufiles. */
export async function jws(
  claims: Claims = {},
  opts: { key?: Keys; typ?: string; kid?: string } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const k = opts.key ?? keys!;
  const body = {
    pro_until: now + 30 * DAY,
    pro_source: 'web',
    donor: false,
    badge: 'pro',
    devices_30d: 1,
    ...claims,
  };
  delete (body as Record<string, unknown>).sub;
  delete (body as Record<string, unknown>).aud;
  delete (body as Record<string, unknown>).iss;
  delete (body as Record<string, unknown>).iat;
  delete (body as Record<string, unknown>).exp;
  if (!claims.cnf) delete (body as Record<string, unknown>).cnf;
  const iat = claims.iat ?? now;
  return new SignJWT(body)
    .setProtectedHeader({ alg: 'ES256', typ: opts.typ ?? 'tsu-ent+jwt', kid: opts.kid ?? (k.jwk.kid) })
    .setIssuer(claims.iss ?? ISSUER)
    .setSubject(claims.sub ?? 'user-1')
    .setAudience(claims.aud ?? 'tsufiles')
    .setIssuedAt(iat)
    .setExpirationTime(claims.exp ?? iat + 7 * DAY)
    .sign(k.privateKey);
}

export async function call(
  path: string,
  init: RequestInit & { token?: string; envOverride?: Partial<Env> } = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.token) headers.set('Authorization', `Bearer ${init.token}`);
  if (init.body && typeof init.body === 'string' && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const req = new Request(`https://sync.test${path}`, { ...init, headers });
  const ctx = createExecutionContext();
  const res = await app.fetch(req, { ...env, ...init.envOverride }, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

export const b64u = (bytes: Uint8Array) => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const bytes = (n: number, fill = 7) => new Uint8Array(n).fill(fill);

export async function digestOf(data: Uint8Array) {
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', data)));
}

export async function push(token: string, items: unknown[], envOverride?: Partial<Env>) {
  return call('/v1/records', { method: 'POST', token, body: JSON.stringify({ items }), envOverride });
}

export async function json<T = any>(res: Response): Promise<T> {
  return (await res.json());
}

export interface DeviceKey {
  privateKey: JoseKey;
  jwk: JWK;
  jkt: string;
}

export async function deviceKey(): Promise<DeviceKey> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk, jkt: await calculateJwkThumbprint(jwk, 'sha256') };
}

/** Bằng chứng DPoP (RFC 9449) cho một yêu cầu tới https://sync.test. */
export async function dpopProof(
  key: DeviceKey,
  method: string,
  path: string,
  token: string,
  o: { iat?: number; jti?: string; ath?: string; htu?: string } = {},
) {
  return new SignJWT({
    htm: method,
    htu: o.htu ?? `https://sync.test${path.split('?')[0]}`,
    iat: o.iat ?? Math.floor(Date.now() / 1000),
    jti: o.jti ?? crypto.randomUUID(),
    ath: o.ath ?? b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)))),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: key.jwk })
    .sign(key.privateKey);
}
