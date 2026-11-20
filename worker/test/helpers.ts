import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey as JoseKey, type JWK } from 'jose';
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
  vi.spyOn(globalThis, 'fetch').mockImplementation((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
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
