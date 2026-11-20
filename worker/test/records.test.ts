import { describe, expect, it, beforeEach } from 'vitest';
import { env } from 'cloudflare:workers';

import { DAY, b64u, bytes, call, json, jws, push, setupIdp } from './helpers';

beforeEach(setupIdp);
const now = () => Math.floor(Date.now() / 1000);
const p = (n: number, fill = 1) => b64u(bytes(n, fill));

describe('402 pro_required (N4: máy chủ kiểm quyền)', () => {
  it('chưa từng có Pro ⇒ đẩy và kéo đều 402', async () => {
    const t = await jws({ sub: 'free-1', pro_until: 0 });
    const r1 = await push(t, [{ id: 'a', payload: p(10) }]);
    expect(r1.status).toBe(402);
    expect(await json(r1)).toMatchObject({ error: 'pro_required', reason: 'no_pro' });
    expect((await call('/v1/records', { token: t })).status).toBe(402);
  });

  it('hết Pro < 90 ngày ⇒ chặn đẩy, vẫn cho kéo', async () => {
    const pro = await jws({ sub: 'lapsed-1' });
    expect((await push(pro, [{ id: 'a', payload: p(10) }])).status).toBe(200);
    const lapsed = await jws({ sub: 'lapsed-1', pro_until: now() - 10 * DAY });
    expect((await push(lapsed, [{ id: 'b', payload: p(10) }])).status).toBe(402);
    const pulled = await call('/v1/records', { token: lapsed });
    expect(pulled.status).toBe(200);
    expect((await json(pulled)).items).toHaveLength(1);
  });

  it('hết Pro > 90 ngày ⇒ kéo 402 grace_expired', async () => {
    const t = await jws({ sub: 'gone-1', pro_until: now() - 91 * DAY });
    const res = await call('/v1/records', { token: t });
    expect(res.status).toBe(402);
    expect((await json(res)).reason).toBe('grace_expired');
  });
});

describe('đồng bộ theo con trỏ rev', () => {
  it('đẩy ⇒ rev tăng dần; kéo since trả đúng phần thay đổi', async () => {
    const t = await jws({ sub: 'rev-1' });
    const r = await json(await push(t, [{ id: 'a', payload: p(10, 1) }, { id: 'b', payload: p(10, 2) }, { id: 'c', payload: p(10, 3) }]));
    expect(r.results.map((x: any) => [x.status, x.rev])).toEqual([['applied', 1], ['applied', 2], ['applied', 3]]);
    expect(r.rev).toBe(3);

    const all = await json(await call('/v1/records?since=0', { token: t }));
    expect(all.items.map((x: any) => x.id)).toEqual(['a', 'b', 'c']);
    expect(all.items[1].payload).toBe(p(10, 2));
    expect(all.next).toBe(3);
    expect(all.more).toBe(false);

    const tail = await json(await call('/v1/records?since=2', { token: t }));
    expect(tail.items.map((x: any) => x.id)).toEqual(['c']);

    const paged = await json(await call('/v1/records?since=0&limit=2', { token: t }));
    expect(paged.items).toHaveLength(2);
    expect(paged.more).toBe(true);
    expect(paged.next).toBe(2);
  });

  it('ghi lặp lại cùng nội dung ⇒ unchanged, không tăng rev, không tính hạn mức hai lần (idempotent)', async () => {
    const t = await jws({ sub: 'idem-1' });
    const items = [{ id: 'x', payload: p(100), base_rev: 0 }];
    expect((await json(await push(t, items))).results[0]).toEqual({ id: 'x', status: 'applied', rev: 1 });
    const before = await json(await call('/v1/account', { token: t }));
    // Thử lại y hệt (kể cả base_rev cũ) - như khi mất phản hồi giữa đường.
    expect((await json(await push(t, items))).results[0]).toEqual({ id: 'x', status: 'unchanged', rev: 1 });
    const after = await json(await call('/v1/account', { token: t }));
    expect(after.rev).toBe(1);
    expect(after.quota.data_bytes).toBe(before.quota.data_bytes);
    expect(after.quota.data_bytes).toBe(100 + 1 + 64);
  });

  it('base_rev lệch ⇒ conflict trả rev hiện tại; khớp ⇒ applied', async () => {
    const t = await jws({ sub: 'cfl-1' });
    await push(t, [{ id: 'x', payload: p(10, 1) }]);
    await push(t, [{ id: 'x', payload: p(10, 2) }]);
    const c = await json(await push(t, [{ id: 'x', payload: p(10, 3), base_rev: 1 }]));
    expect(c.results[0]).toEqual({ id: 'x', status: 'conflict', rev: 2 });
    const ok = await json(await push(t, [{ id: 'x', payload: p(10, 3), base_rev: 2 }]));
    expect(ok.results[0]).toEqual({ id: 'x', status: 'applied', rev: 3 });
    const create = await json(await push(t, [{ id: 'x', payload: p(10, 4), base_rev: 0 }]));
    expect(create.results[0].status).toBe('conflict');
  });

  it('xoá ⇒ bia mộ được kéo về, dung lượng giảm', async () => {
    const t = await jws({ sub: 'del-1' });
    await push(t, [{ id: 'x', payload: p(1000) }]);
    const r = await json(await push(t, [{ id: 'x', deleted: true }]));
    expect(r.results[0]).toEqual({ id: 'x', status: 'applied', rev: 2 });
    const pulled = await json(await call('/v1/records?since=1', { token: t }));
    expect(pulled.items).toEqual([{ id: 'x', rev: 2, deleted: true }]);
    expect((await json(await call('/v1/account', { token: t }))).quota.data_bytes).toBe(1 + 64);
  });

  it('mục trùng id / payload hỏng bị từ chối riêng, mục khác vẫn ghi', async () => {
    const t = await jws({ sub: 'rej-1' });
    const r = await json(
      await push(t, [
        { id: 'a', payload: p(5) },
        { id: 'a', payload: p(6) },
        { id: 'b', payload: 'không-phải-base64url!' },
        { id: 'c' },
        { id: 'd', deleted: true, payload: p(3) },
      ]),
    );
    expect(r.results.map((x: any) => x.status)).toEqual(['applied', 'rejected', 'rejected', 'rejected', 'rejected']);
    expect(r.results[1].reason).toBe('duplicate');
    expect(r.results[2].reason).toBe('invalid_payload');
  });

  it('khung yêu cầu sai ⇒ 400; lô > 100 mục ⇒ 400; thân quá lớn ⇒ 413', async () => {
    const t = await jws({ sub: 'bad-1' });
    expect((await push(t, [{ id: 'có dấu cách', payload: p(5) }])).status).toBe(400);
    expect((await push(t, Array.from({ length: 101 }, (_, i) => ({ id: `i${i}`, payload: p(5) })))).status).toBe(400);
    expect((await call('/v1/records', { method: 'POST', token: t, body: '{' })).status).toBe(400);
    const huge = Array.from({ length: 60 }, (_, i) => ({ id: `h${i}`, payload: p(60 * 1024) }));
    const res = await push(t, huge);
    expect(res.status).toBe(413);
    expect((await call('/v1/records?since=-1', { token: t })).status).toBe(400);
  });

  it('không gian tên tách biệt: cùng sub, khác sản phẩm không thấy dữ liệu của nhau', async () => {
    const a = await jws({ sub: 'ns-1', aud: 'tsufiles' });
    const b = await jws({ sub: 'ns-1', aud: 'lotus-share' });
    await push(a, [{ id: 'x', payload: p(10) }]);
    expect((await json(await call('/v1/records', { token: b }))).items).toHaveLength(0);
    expect((await json(await call('/v1/records', { token: a }))).items).toHaveLength(1);
  });

  it('máy chủ không lưu sub gốc (chỉ băm)', async () => {
    await push(await jws({ sub: 'sub-bi-mat-42' }), [{ id: 'x', payload: p(10) }]);
    const rows = await env.DB.prepare('SELECT sub_key FROM accounts').all<{ sub_key: string }>();
    expect(rows.results.every((r) => /^[0-9a-f]{64}$/.test(r.sub_key))).toBe(true);
  });

  it('hai thiết bị đẩy đồng thời ⇒ cả hai được ghi, rev không trùng', async () => {
    const t = await jws({ sub: 'race-1' });
    const [r1, r2] = await Promise.all([push(t, [{ id: 'a', payload: p(10, 1) }]), push(t, [{ id: 'b', payload: p(10, 2) }])]);
    const revs = [(await json(r1)).results[0].rev, (await json(r2)).results[0].rev].sort();
    expect(revs).toEqual([1, 2]);
    expect((await json(await call('/v1/account', { token: t }))).quota.data_bytes).toBe(2 * (10 + 1 + 64));
  });
});

describe('hạn mức (PRODUCT_POLICY 7.5, FREE_TIER_STACK 3.1)', () => {
  it('vượt hạn mức dữ liệu ⇒ 413 quota_exceeded, không ghi gì của lô', async () => {
    // Không gian tên "tiny": 0,01 MiB = 10485 byte.
    const t = await jws({ sub: 'q-1', aud: 'tiny' });
    expect((await push(t, [{ id: 'a', payload: p(6000) }])).status).toBe(200);
    const res = await push(t, [{ id: 'b', payload: p(3000) }, { id: 'c', payload: p(3000) }]);
    expect(res.status).toBe(413);
    expect(await json(res)).toMatchObject({ error: 'quota_exceeded', kind: 'data', limit: 10485 });
    expect((await json(await call('/v1/records', { token: t }))).items.map((x: any) => x.id)).toEqual(['a']);
  });

  it('trần toàn dịch vụ ⇒ 507 capacity_reached', async () => {
    const t = await jws({ sub: 'cap-1' });
    const res = await push(t, [{ id: 'a', payload: p(60_000) }], { GLOBAL_DATA_BUDGET_MIB: '0.001' });
    expect(res.status).toBe(507);
    expect((await json(res)).error).toBe('capacity_reached');
  });

  it('quá tần suất ghi ⇒ 429 có Retry-After', async () => {
    const t = await jws({ sub: 'rl-1' });
    const o = { WRITE_RATE_PER_MIN: '2' };
    expect((await push(t, [{ id: 'a', payload: p(5, 1) }], o)).status).toBe(200);
    expect((await push(t, [{ id: 'a', payload: p(5, 2) }], o)).status).toBe(200);
    const res = await push(t, [{ id: 'a', payload: p(5, 3) }], o);
    expect(res.status).toBe(429);
    expect(Number(res.headers.get('Retry-After'))).toBeGreaterThan(0);
  });
});
