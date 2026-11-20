import { GRACE_MS } from './config';
import type { Env } from './env';

/**
 * Dọn dữ liệu theo lô nhỏ (ADR-0001 mục 3.7). Không dùng Cron (tài khoản Cloudflare đã dùng hết 5 Cron gói Free):
 * chạy kèm ~1% yêu cầu và ngay sau `DELETE /v1/account`. Mỗi lượt xoá tối đa CHUNK dòng mỗi bảng cho tối đa
 * ACCOUNTS_PER_RUN tài khoản - giữ dưới 50 truy vấn/lượt gọi và 100.000 dòng ghi/ngày của D1 Free.
 * - `purge_requested = 1`: người dùng yêu cầu xoá - luôn chạy.
 * - Hết Pro quá 90 ngày: chỉ khi `PURGE_ENABLED = "on"` (xem ADR-0001 mục 5: rủi ro `pro_until` cũ).
 */
const CHUNK = 500;
const ACCOUNTS_PER_RUN = 2;
const R2_DELETE_MAX = 500;

interface Target {
  ns: string;
  sub_key: string;
  data_bytes: number;
  file_bytes: number;
}

export async function runMaintenance(env: Env, now = Date.now()): Promise<{ purged: number; pending: number }> {
  const expiryOn = env.PURGE_ENABLED === 'on';
  const targets = await env.DB.prepare(
    `SELECT ns, sub_key, data_bytes, file_bytes FROM accounts
     WHERE purge_requested = 1 OR (?1 = 1 AND pro_until > 0 AND pro_until < ?2)
     LIMIT ?3`,
  )
    .bind(expiryOn ? 1 : 0, now - GRACE_MS, ACCOUNTS_PER_RUN)
    .all<Target>();

  let purged = 0;
  let pending = 0;
  for (const t of targets.results) {
    // Chặn ghi mới trong lúc xoá (đẩy/tải nhận 409 purge_in_progress).
    await env.DB.prepare('UPDATE accounts SET purge_requested = 1 WHERE ns = ? AND sub_key = ?').bind(t.ns, t.sub_key).run();

    const prefix = `${t.ns}/${t.sub_key}/`;
    const listed = await env.FILES.list({ prefix, limit: R2_DELETE_MAX });
    if (listed.objects.length > 0) await env.FILES.delete(listed.objects.map((o) => o.key));

    const [rec, fil] = await env.DB.batch([
      env.DB.prepare(
        'DELETE FROM records WHERE ns = ?1 AND sub_key = ?2 AND id IN (SELECT id FROM records WHERE ns = ?1 AND sub_key = ?2 LIMIT ?3)',
      ).bind(t.ns, t.sub_key, CHUNK),
      env.DB.prepare(
        'DELETE FROM files WHERE ns = ?1 AND sub_key = ?2 AND id IN (SELECT id FROM files WHERE ns = ?1 AND sub_key = ?2 LIMIT ?3)',
      ).bind(t.ns, t.sub_key, CHUNK),
    ]);
    const more = listed.truncated || (rec?.meta.changes ?? 0) >= CHUNK || (fil?.meta.changes ?? 0) >= CHUNK;
    if (more) {
      pending++;
      continue;
    }
    await env.DB.batch([
      env.DB.prepare('UPDATE totals SET data_bytes = MAX(0, data_bytes - ?1), file_bytes = MAX(0, file_bytes - ?2) WHERE id = 1').bind(
        t.data_bytes,
        t.file_bytes,
      ),
      env.DB.prepare('DELETE FROM accounts WHERE ns = ? AND sub_key = ?').bind(t.ns, t.sub_key),
    ]);
    purged++;
  }
  await env.DB.prepare('DELETE FROM rate_limits WHERE key IN (SELECT key FROM rate_limits WHERE window_start < ? LIMIT ?)')
    .bind(now - 3600_000, CHUNK)
    .run();
  return { purged, pending };
}
