import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';

import { DAY, bytes, call, digestOf, json, jws, setupIdp } from './helpers';

beforeEach(setupIdp);

async function upload(token: string, id: string, data: Uint8Array, digest?: string) {
  return call(`/v1/files/${id}`, {
    method: 'PUT',
    token,
    body: data,
    headers: { 'Content-Length': String(data.length), 'X-Tsu-Digest': digest ?? (await digestOf(data)) },
  });
}

describe('tệp bản mã trên R2', () => {
  it('tải lên ⇒ 201, tải lại y hệt ⇒ unchanged, tải xuống đúng byte + digest', async () => {
    const t = await jws({ sub: 'f-1' });
    const data = bytes(5000, 9);
    const r1 = await upload(t, 'anh-1', data);
    expect(r1.status).toBe(201);
    expect(await json(r1)).toEqual({ id: 'anh-1', status: 'applied', rev: 1 });
    expect(await json(await upload(t, 'anh-1', data))).toEqual({ id: 'anh-1', status: 'unchanged', rev: 1 });

    const got = await call('/v1/files/anh-1', { token: t });
    expect(got.status).toBe(200);
    expect(got.headers.get('X-Tsu-Digest')).toBe(await digestOf(data));
    expect(new Uint8Array(await got.arrayBuffer())).toEqual(data);
    expect((await json(await call('/v1/account', { token: t }))).quota.file_bytes).toBe(5000);
  });

  it('digest không khớp nội dung ⇒ 400, không ghi', async () => {
    const t = await jws({ sub: 'f-2' });
    const res = await upload(t, 'x', bytes(100, 1), await digestOf(bytes(100, 2)));
    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe('digest_mismatch');
    expect((await call('/v1/files/x', { token: t })).status).toBe(404);
  });

  it('thiếu digest ⇒ 400; tệp quá 64 MiB ⇒ 413 (theo Content-Length)', async () => {
    const t = await jws({ sub: 'f-3' });
    const noDigest = await call('/v1/files/x', { method: 'PUT', token: t, body: bytes(10), headers: { 'Content-Length': '10' } });
    expect(noDigest.status).toBe(400);
    const big = await call('/v1/files/x', {
      method: 'PUT',
      token: t,
      body: bytes(10),
      headers: { 'Content-Length': String(65 * 1024 * 1024), 'X-Tsu-Digest': await digestOf(bytes(10)) },
    });
    expect(big.status).toBe(413);
  });

  it('danh sách theo rev dùng chung con trỏ với bản ghi; xoá ⇒ bia mộ + giảm dung lượng', async () => {
    const t = await jws({ sub: 'f-4' });
    await call('/v1/records', { method: 'POST', token: t, body: JSON.stringify({ items: [{ id: 'r', payload: 'AQID' }] }) });
    await upload(t, 'a', bytes(300));
    await upload(t, 'b', bytes(200));
    const list = await json(await call('/v1/files?since=0', { token: t }));
    expect(list.items.map((x: any) => [x.id, x.rev, x.size])).toEqual([['a', 2, 300], ['b', 3, 200]]);

    const del = await call('/v1/files/a', { method: 'DELETE', token: t });
    expect(await json(del)).toEqual({ id: 'a', status: 'applied', rev: 4 });
    expect((await call('/v1/files/a', { token: t })).status).toBe(404);
    expect((await json(await call('/v1/files?since=3', { token: t }))).items).toEqual([{ id: 'a', rev: 4, deleted: true }]);
    expect((await json(await call('/v1/account', { token: t }))).quota.file_bytes).toBe(200);
    expect(await env.FILES.head(`tsufiles/${'x'.repeat(0)}`)).toBeNull();
  });

  it('vượt hạn mức tệp ⇒ 413 quota_exceeded kind files', async () => {
    // "tiny": 0,02 MiB = 20971 byte.
    const t = await jws({ sub: 'f-5', aud: 'tiny' });
    expect((await upload(t, 'a', bytes(15000))).status).toBe(201);
    const res = await upload(t, 'b', bytes(8000));
    expect(res.status).toBe(413);
    expect(await json(res)).toMatchObject({ error: 'quota_exceeded', kind: 'files' });
    // Ghi đè chính tệp đó với cỡ nhỏ hơn vẫn được (tính phần chênh).
    expect((await upload(t, 'a', bytes(20000, 3))).status).toBe(200);
  });

  it('không có Pro ⇒ tải lên 402; hết Pro < 90 ngày vẫn tải xuống + xoá được', async () => {
    const pro = await jws({ sub: 'f-6' });
    await upload(pro, 'a', bytes(10));
    const lapsed = await jws({ sub: 'f-6', pro_until: Math.floor(Date.now() / 1000) - DAY });
    expect((await upload(lapsed, 'b', bytes(10))).status).toBe(402);
    expect((await call('/v1/files/a', { token: lapsed })).status).toBe(200);
    expect((await call('/v1/files/a', { method: 'DELETE', token: lapsed })).status).toBe(200);
  });
});
