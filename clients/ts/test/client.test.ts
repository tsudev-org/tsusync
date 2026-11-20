import { describe, expect, it } from 'vitest';
import { createKeys, ProRequiredError, ready, SyncClient, SyncHttpError, SyncSession, b64u } from '../src/index.ts';

type Call = { url: string; init: RequestInit };
function fakeFetch(responses: Response[]) {
  const calls: Call[] = [];
  const f = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const r = responses.shift();
    if (!r) throw new Error('hết phản hồi giả');
    return r;
  }) as unknown as typeof fetch;
  return { f, calls };
}
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const hdr = (c: Call | undefined, k: string) => (c?.init.headers as Record<string, string>)[k];

await ready();

describe('SyncClient', () => {
  it('401 stale ⇒ lấy JWS mới rồi thử lại ĐÚNG một lần', async () => {
    const { f, calls } = fakeFetch([
      json(401, { error: 'invalid_token', reason: 'stale' }),
      json(401, { error: 'invalid_token', reason: 'stale' }),
    ]);
    const asked: boolean[] = [];
    const c = new SyncClient({ baseUrl: 'https://s.test/', fetch: f, getJws: async (force) => (asked.push(force), force ? 'moi' : 'cu') });
    await expect(c.pullRecords()).rejects.toMatchObject({ status: 401, reason: 'stale' });
    expect(asked).toEqual([false, true]);
    expect(calls.map((x) => hdr(x, 'Authorization'))).toEqual(['Bearer cu', 'Bearer moi']);
    expect(calls[0]?.url).toBe('https://s.test/v1/records?since=0&limit=500');
  });

  it('401 khác stale không thử lại', async () => {
    const { f, calls } = fakeFetch([json(401, { error: 'invalid_token', reason: 'invalid' })]);
    const c = new SyncClient({ baseUrl: 'https://s.test', fetch: f, getJws: async () => 'j' });
    await expect(c.account()).rejects.toBeInstanceOf(SyncHttpError);
    expect(calls).toHaveLength(1);
  });

  it('402 ⇒ ProRequiredError mang reason, không thử lại', async () => {
    const { f, calls } = fakeFetch([json(402, { error: 'pro_required', reason: 'grace_expired' })]);
    const c = new SyncClient({ baseUrl: 'https://s.test', fetch: f, getJws: async () => 'j' });
    const err = await c.pullRecords().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProRequiredError);
    expect((err as ProRequiredError).reason).toBe('grace_expired');
    expect(calls).toHaveLength(1);
  });

  it('503 mang Retry-After', async () => {
    const { f } = fakeFetch([json(503, { error: 'busy' }, { 'Retry-After': '5' })]);
    const c = new SyncClient({ baseUrl: 'https://s.test', fetch: f, getJws: async () => 'j' });
    await expect(c.listFiles()).rejects.toMatchObject({ status: 503, code: 'busy', retryAfter: 5 });
  });

  it('DPoP: Authorization DPoP + bằng chứng mới mỗi yêu cầu, htu không có query', async () => {
    const { f, calls } = fakeFetch([json(200, { items: [], next: 0, more: false })]);
    const seen: string[] = [];
    const c = new SyncClient({
      baseUrl: 'https://s.test',
      fetch: f,
      getJws: async () => 'jws',
      installationId: 'AAAAAAAAAAAAAAAAAAAAAA',
      dpop: async (m, u, j) => (seen.push(`${m} ${u} ${j}`), 'proof'),
    });
    await c.pullRecords(7, 10);
    expect(seen).toEqual(['GET https://s.test/v1/records jws']);
    expect(hdr(calls[0], 'Authorization')).toBe('DPoP jws');
    expect(hdr(calls[0], 'DPoP')).toBe('proof');
    expect(hdr(calls[0], 'X-Tsu-Installation')).toBe('AAAAAAAAAAAAAAAAAAAAAA');
  });

  it('từ chối id chứa bản rõ và mã cài đặt sai độ dài', () => {
    expect(() => new SyncClient({ baseUrl: 'https://s.test', getJws: async () => 'j', installationId: 'ngắn' })).toThrow(TypeError);
    const c = new SyncClient({ baseUrl: 'https://s.test', getJws: async () => 'j', fetch: fakeFetch([]).f });
    return expect(c.getFile('hoá đơn.jpg')).rejects.toBeInstanceOf(TypeError);
  });
});

describe('SyncSession', () => {
  const keys = createKeys('mật khẩu đồng bộ thử', { ops: 2, mem: 19 * 1024 * 1024 });

  it('đẩy bản ghi đã mã hoá, kéo về mở lại được; bia mộ không có payload', async () => {
    const { f, calls } = fakeFetch([json(200, { results: [], rev: 2 })]);
    const s = new SyncSession(new SyncClient({ baseUrl: 'https://s.test', fetch: f, getJws: async () => 'j' }), keys, 'tsudev-test');
    const data = new TextEncoder().encode('bí mật');
    await s.pushPlain([{ id: 'r1', data, base_rev: 0 }, { id: 'r2', deleted: true }]);
    const sent = JSON.parse(String(calls[0]?.init.body)) as { items: { id: string; payload?: string; deleted?: boolean; base_rev?: number }[] };
    expect(sent.items[1]).toEqual({ id: 'r2', deleted: true });
    expect(sent.items[0]?.base_rev).toBe(0);
    expect(new TextDecoder().decode(s.openRecord({ id: 'r1', rev: 1, deleted: false, payload: sent.items[0]!.payload! })!)).toBe('bí mật');
    expect(s.openRecord({ id: 'r2', rev: 2, deleted: true })).toBeNull();
    // Máy chủ tráo payload sang id khác ⇒ không mở được.
    expect(() => s.openRecord({ id: 'r3', rev: 1, deleted: false, payload: sent.items[0]!.payload! })).toThrow();
  });

  it('tải tệp lên kèm X-Tsu-Digest = SHA-256 bản mã, tải về mở lại được', async () => {
    const { f, calls } = fakeFetch([json(201, { id: 'f1', status: 'applied', rev: 1 })]);
    const s = new SyncSession(new SyncClient({ baseUrl: 'https://s.test', fetch: f, getJws: async () => 'j' }), keys, 'tsudev-test');
    const data = new Uint8Array(70_000).fill(9);
    await s.putPlainFile('f1', data);
    const body = calls[0]?.init.body as Uint8Array;
    const digest = b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', body as BufferSource)));
    expect(hdr(calls[0], 'X-Tsu-Digest')).toBe(digest);
    const back = fakeFetch([new Response(body as BodyInit, { status: 200 })]);
    const s2 = new SyncSession(new SyncClient({ baseUrl: 'https://s.test', fetch: back.f, getJws: async () => 'j' }), keys, 'tsudev-test');
    expect((await s2.getPlainFile('f1')).length).toBe(70_000);
  });
});

describe('baseUrl', () => {
  it('chỉ nhận https (http chỉ cho localhost), không nhận thông tin đăng nhập/query trong URL', () => {
    const make = (baseUrl: string) => () => new SyncClient({ baseUrl, getJws: async () => 'j', fetch: fakeFetch([]).f });
    for (const ok of ['https://sync.tsudev.com', 'https://s.test/', 'http://localhost:8787', 'http://127.0.0.1:8787/', 'http://[::1]:8787']) {
      expect(make(ok)).not.toThrow();
    }
    for (const bad of ['http://sync.tsudev.com', 'http://localhost.evil.test', 'ftp://s.test', 's.test', '', 'https://u:p@s.test', 'https://s.test/?x=1', 'javascript:alert(1)']) {
      expect(make(bad)).toThrow(TypeError);
    }
  });
});

