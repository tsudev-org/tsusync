import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';

import { decryptSub } from '../src/crypto';
import type { Env } from '../src/env';
import { runMaintenance } from '../src/maintenance';
import { DAY, b64u, bytes, call, digestOf, json, jws, push, rpKey, setStatusResponder, setupIdp, statusCalls, verifyAssertion } from './helpers';

beforeEach(setupIdp);

const count = async (table: string) =>
  (await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())!.n;

async function seed(sub: string) {
  const t = await jws({ sub });
  await push(t, [{ id: 'a', payload: b64u(bytes(50)) }, { id: 'b', payload: b64u(bytes(60)) }]);
  const data = bytes(400);
  await call('/v1/files/f', { method: 'PUT', token: t, body: data, headers: { 'Content-Length': '400', 'X-Tsu-Digest': await digestOf(data) } });
  return t;
}

describe('xoá dữ liệu', () => {
  it('DELETE /v1/account ⇒ 202, chặn ghi trong lúc xoá, dọn sạch D1 + R2 + tổng', async () => {
    const t = await seed('life-1');
    const totalsBefore = await env.DB.prepare('SELECT data_bytes, file_bytes FROM totals').first<{ data_bytes: number; file_bytes: number }>();
    expect(totalsBefore!.file_bytes).toBeGreaterThanOrEqual(400);

    // Chặn dọn chạy ngay (waitUntil) để kiểm trạng thái "đang xoá": đặt cờ trực tiếp.
    await env.DB.prepare("UPDATE accounts SET purge_requested = 1 WHERE ns = 'tsufiles'").run();
    const blocked = await push(t, [{ id: 'z', payload: 'AQID' }]);
    expect(blocked.status).toBe(409);
    expect((await json(blocked)).error).toBe('purge_in_progress');

    const res = await call('/v1/account', { method: 'DELETE', token: t });
    expect(res.status).toBe(202);
    await runMaintenance(env);

    const acc = await json(await call('/v1/account', { token: t }));
    expect(acc.rev).toBe(0);
    expect(acc.quota.data_bytes).toBe(0);
    expect((await env.FILES.list({ prefix: 'tsufiles/' })).objects.filter((o) => o.key.endsWith('/f'))).toHaveLength(0);
    const totalsAfter = await env.DB.prepare('SELECT data_bytes, file_bytes FROM totals').first<{ data_bytes: number; file_bytes: number }>();
    expect(totalsAfter!.file_bytes).toBe(totalsBefore!.file_bytes - 400);

    // Sau khi xoá, tài khoản bắt đầu lại từ rev 0.
    expect((await json(await push(t, [{ id: 'n', payload: 'AQID' }]))).results[0].rev).toBe(1);
  });

  const t0 = () => Math.floor(Date.now() / 1000);
  const FUTURE = () => Date.now() + 91 * DAY * 1000;
  const withRp = async (o: Partial<Env> = {}) => ({ ...env, RP_PRIVATE_JWK: (await rpKey()).privateJwk, ...o }) as Env;
  /** Tạo dữ liệu rồi báo (bằng JWS mới hơn) rằng Pro đã hết hạn 1 phút trước. */
  async function seedLapsed(sub: string) {
    const t = await seed(sub);
    await call('/v1/account', { token: await jws({ sub, pro_until: t0() - 60, iat: t0() + 1 }) });
    return t;
  }
  const revOf = async (sub: string) => (await json(await call('/v1/account', { token: await jws({ sub, iat: t0() + 2 }) }))).rev as number;

  it('quá 90 ngày + tsudev.com xác nhận KHÔNG gia hạn ⇒ xoá; tài khoản còn Pro giữ nguyên', async () => {
    await seed('life-keep');
    await seedLapsed('life-gone');
    setStatusResponder(({ subs }) => Response.json({ results: Object.fromEntries(subs.map((s) => [s, { status: 'ok', pro_until: t0() - 60 }])) }));
    const e = await withRp();
    await runMaintenance(e, Date.now() + 89 * DAY * 1000);
    expect(statusCalls).toHaveLength(0); // chưa tới 90 ngày ⇒ không hỏi
    await runMaintenance(e, FUTURE());
    await runMaintenance(e, FUTURE());
    expect(statusCalls.length).toBeGreaterThan(0);
    const call0 = statusCalls.find((c) => c.body.subs.includes('life-gone'))!;
    expect(call0.body.client_id).toBe('tsufiles');
    expect(call0.body.subs).not.toContain('life-keep');
    const a = await verifyAssertion(call0.auth);
    expect(a.exp! - a.iat!).toBeLessThanOrEqual(300);
    expect(typeof a.jti).toBe('string');
    expect(await revOf('life-gone')).toBe(0);
    expect(await revOf('life-keep')).toBe(3);
  });

  it('gia hạn trên web mà KHÔNG mở app ⇒ không xoá, cập nhật pro_until từ tsudev.com', async () => {
    await seedLapsed('life-renewed');
    const renewedUntil = t0() + 365 * DAY;
    setStatusResponder(({ subs }) => Response.json({ results: Object.fromEntries(subs.map((s) => [s, { status: 'ok', pro_until: renewedUntil }])) }));
    await runMaintenance(await withRp(), FUTURE());
    await runMaintenance(await withRp(), FUTURE());
    expect(statusCalls.some((c) => c.body.subs.includes('life-renewed'))).toBe(true);
    expect(await revOf('life-renewed')).toBe(3);
    const rows = await env.DB.prepare('SELECT COUNT(*) AS n FROM accounts WHERE pro_until = ?').bind(renewedUntil * 1000).first<{ n: number }>();
    expect(rows!.n).toBeGreaterThanOrEqual(1);
  });

  it('kênh trạng thái lỗi / unknown_subject ⇒ hoãn (không xoá), hỏi lại tối đa 1 lần/ngày', async () => {
    await seedLapsed('life-down');
    await seedLapsed('life-unknown');
    setStatusResponder(({ subs }) =>
      subs.includes('life-down') ? new Response('bad gateway', { status: 502 }) : Response.json({ results: { 'life-unknown': { status: 'unknown_subject' } } }),
    );
    const e = await withRp();
    await runMaintenance(e, FUTURE());
    const calls = statusCalls.length;
    expect(calls).toBeGreaterThan(0);
    await runMaintenance(e, FUTURE());
    expect(statusCalls.length).toBe(calls); // đã đánh dấu purge_checked_at ⇒ không dội tsudev.com
    expect(await revOf('life-down')).toBe(3);
    expect(await revOf('life-unknown')).toBe(3);
  });

  it('tài khoản đã xoá ở tsudev.com ⇒ xoá', async () => {
    await seedLapsed('life-deleted');
    setStatusResponder(({ subs }) => Response.json({ results: Object.fromEntries(subs.map((s) => [s, { status: 'deleted' }])) }));
    await runMaintenance(await withRp(), FUTURE());
    await runMaintenance(await withRp(), FUTURE());
    expect(await revOf('life-deleted')).toBe(0);
  });

  it('PURGE_MODE = off hoặc thiếu khoá RP ⇒ không hỏi, không tự xoá', async () => {
    await seedLapsed('life-off');
    await runMaintenance(await withRp({ PURGE_MODE: 'off' }), Date.now() + 365 * DAY * 1000);
    await runMaintenance(env, Date.now() + 365 * DAY * 1000); // env không có RP_PRIVATE_JWK
    expect(statusCalls).toHaveLength(0);
    expect(await revOf('life-off')).toBe(3);
    expect(await count('records')).toBeGreaterThan(0);
  });

  it('sub chỉ lưu dạng mã hoá AES-GCM (AAD = không gian tên), giải được bằng SUB_ENC_KEY', async () => {
    await seed('sub-ma-hoa-77');
    const rows = await env.DB.prepare('SELECT ns, sub_enc FROM accounts WHERE sub_enc IS NOT NULL').all<{ ns: string; sub_enc: ArrayBuffer }>();
    expect(rows.results.length).toBeGreaterThan(0);
    const plain = new TextEncoder().encode('sub-ma-hoa-77');
    const found = await Promise.all(rows.results.map((r) => decryptSub(env.SUB_ENC_KEY, r.ns, r.sub_enc)));
    expect(found).toContain('sub-ma-hoa-77');
    for (const r of rows.results) expect(new Uint8Array(r.sub_enc).join(',')).not.toContain(plain.join(','));
    // Sai không gian tên (AAD) ⇒ không giải được.
    expect(await decryptSub(env.SUB_ENC_KEY, 'lotus-share', rows.results.find((r, i) => found[i] === 'sub-ma-hoa-77')!.sub_enc)).toBeNull();
  });

  it('JWS cũ hơn không ghi đè pro_until đã biết (chống phát lại)', async () => {
    const sub = 'replay-1';
    const t0 = Math.floor(Date.now() / 1000);
    await push(await jws({ sub, pro_until: t0 + 30 * DAY, iat: t0 }), [{ id: 'a', payload: 'AQID' }]);
    await call('/v1/account', { token: await jws({ sub, pro_until: 5, iat: t0 + 1 }) });
    await call('/v1/account', { token: await jws({ sub, pro_until: t0 + 30 * DAY, iat: t0 - 100 }) });
    const subKey = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`tsusync|${sub}`)))]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const row = await env.DB.prepare('SELECT pro_until, pro_iat FROM accounts WHERE sub_key = ?').bind(subKey).first<{ pro_until: number; pro_iat: number }>();
    expect(row).toEqual({ pro_until: 5000, pro_iat: t0 + 1 });
  });
});
