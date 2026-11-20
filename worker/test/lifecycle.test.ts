import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';

import { runMaintenance } from '../src/maintenance';
import { DAY, b64u, bytes, call, digestOf, json, jws, push, setupIdp } from './helpers';

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

  it('hết Pro quá 90 ngày ⇒ tự xoá khi PURGE_ENABLED = on; chưa quá ⇒ giữ', async () => {
    const keep = await seed('life-keep');
    const gone = await seed('life-gone');
    // JWS mới hơn báo Pro đã hết hạn (lưu pro_until), rồi tua thời gian.
    const lapsedAt = Math.floor(Date.now() / 1000) - 60;
    await call('/v1/account', { token: await jws({ sub: 'life-gone', pro_until: lapsedAt, iat: Math.floor(Date.now() / 1000) + 1 }) });
    await runMaintenance(env, Date.now() + 89 * DAY * 1000);
    expect((await json(await call('/v1/account', { token: gone }))).rev).toBeGreaterThan(0);

    await runMaintenance(env, Date.now() + 90 * DAY * 1000);
    await runMaintenance(env, Date.now() + 90 * DAY * 1000);
    const rows = await env.DB.prepare('SELECT COUNT(*) AS n FROM records r JOIN accounts a USING (ns, sub_key)').first<{ n: number }>();
    expect(rows!.n).toBeGreaterThan(0); // còn của life-keep
    expect((await json(await call('/v1/account', { token: keep }))).rev).toBe(3);
    expect((await json(await call('/v1/account', { token: gone }))).rev).toBe(0);
  });

  it('PURGE_ENABLED = off ⇒ không tự xoá theo hạn (chỉ xoá theo yêu cầu)', async () => {
    const t = await seed('life-off');
    await call('/v1/account', { token: await jws({ sub: 'life-off', pro_until: 1, iat: Math.floor(Date.now() / 1000) + 1 }) });
    await runMaintenance({ ...env, PURGE_ENABLED: 'off' }, Date.now() + 365 * DAY * 1000);
    expect((await json(await call('/v1/account', { token: t }))).rev).toBe(3);
    expect(await count('records')).toBeGreaterThan(0);
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
