import { GRACE_MS } from './config';
import { decryptSub } from './crypto';
import type { Env } from './env';
import { fetchSubjectStatus, rpConfigured } from './rp';

/**
 * Dọn dữ liệu theo lô nhỏ (ADR-0001 mục 3.7). Không dùng Cron (tài khoản Cloudflare đã dùng hết 5 Cron gói Free):
 * chạy kèm ~1% yêu cầu và ngay sau `DELETE /v1/account`. Mỗi lượt xoá tối đa CHUNK dòng mỗi bảng cho tối đa
 * ACCOUNTS_PER_RUN tài khoản - giữ dưới 50 truy vấn/lượt gọi và 100.000 dòng ghi/ngày của D1 Free.
 * - `purge_requested = 1` (người dùng yêu cầu, hoặc đã xác minh hết hạn): xoá theo lô - luôn chạy.
 * - Hết Pro quá 90 ngày theo `pro_until` đã biết: KHÔNG xoá ngay. `PURGE_MODE = "verified"` (mặc định) hỏi lại
 *   tsudev.com qua kênh trạng thái (rp.ts) - đã gia hạn ⇒ cập nhật `pro_until`, giữ dữ liệu; xác nhận hết hạn quá
 *   90 ngày hoặc tài khoản đã xoá ⇒ đánh dấu `purge_requested`; không hỏi được / không rõ ⇒ hoãn, hỏi lại sau 24 giờ.
 *   Không có `sub_enc` hoặc chưa cấu hình kênh RP ⇒ không bao giờ tự xoá (ADR-0002).
 */
const CHUNK = 500;
const ACCOUNTS_PER_RUN = 2;
const R2_DELETE_MAX = 500;
const VERIFY_PER_RUN = 20;
const VERIFY_EVERY_MS = 24 * 3600 * 1000;

interface Target {
  ns: string;
  sub_key: string;
  data_bytes: number;
  file_bytes: number;
}

interface Candidate {
  ns: string;
  sub_key: string;
  sub_enc: ArrayBuffer | null;
}

/** Hỏi tsudev.com cho các tài khoản đã quá 90 ngày theo `pro_until` đã biết. Trả số tài khoản được đánh dấu xoá. */
export async function verifyExpired(env: Env, now = Date.now()): Promise<number> {
  if ((env.PURGE_MODE ?? 'verified') !== 'verified' || !rpConfigured(env)) return 0;
  const rows = await env.DB.prepare(
    `SELECT ns, sub_key, sub_enc FROM accounts
     WHERE purge_requested = 0 AND pro_until > 0 AND pro_until < ?1 AND purge_checked_at < ?2
     LIMIT ?3`,
  )
    .bind(now - GRACE_MS, now - VERIFY_EVERY_MS, VERIFY_PER_RUN)
    .all<Candidate>();
  const byNs = new Map<string, { sub: string; subKey: string }[]>();
  const checked: D1PreparedStatement[] = [];
  const markChecked = (ns: string, subKey: string) =>
    env.DB.prepare('UPDATE accounts SET purge_checked_at = ?3 WHERE ns = ?1 AND sub_key = ?2').bind(ns, subKey, now);
  for (const r of rows.results) {
    const sub = await decryptSub(env.SUB_ENC_KEY, r.ns, r.sub_enc);
    if (!sub) {
      checked.push(markChecked(r.ns, r.sub_key));
      continue;
    }
    const list = byNs.get(r.ns) ?? [];
    list.push({ sub, subKey: r.sub_key });
    byNs.set(r.ns, list);
  }
  let marked = 0;
  for (const [ns, list] of byNs) {
    let statuses: Awaited<ReturnType<typeof fetchSubjectStatus>>;
    try {
      statuses = await fetchSubjectStatus(env, ns, list.map((x) => x.sub));
    } catch (e) {
      console.warn('purge_verify_unavailable', e instanceof Error ? e.message.slice(0, 32) : 'error');
      for (const x of list) checked.push(markChecked(ns, x.subKey));
      continue;
    }
    for (const x of list) {
      const st = statuses.get(x.sub);
      if (st?.status === 'ok' && st.proUntil + GRACE_MS > now) {
        // Đã gia hạn (ví dụ trên web) mà app chưa mở: cập nhật hạn, GIỮ dữ liệu.
        checked.push(
          env.DB.prepare(
            'UPDATE accounts SET pro_until = ?3, pro_iat = MAX(pro_iat, ?4), purge_checked_at = ?5 WHERE ns = ?1 AND sub_key = ?2',
          ).bind(ns, x.subKey, st.proUntil, Math.floor(now / 1000), now),
        );
      } else if (st?.status === 'deleted' || st?.status === 'ok') {
        checked.push(
          env.DB.prepare('UPDATE accounts SET purge_requested = 1, purge_checked_at = ?3 WHERE ns = ?1 AND sub_key = ?2').bind(ns, x.subKey, now),
        );
        marked++;
      } else {
        checked.push(markChecked(ns, x.subKey));
      }
    }
  }
  if (checked.length > 0) await env.DB.batch(checked);
  return marked;
}

export async function runMaintenance(env: Env, now = Date.now()): Promise<{ purged: number; pending: number; marked: number }> {
  const marked = await verifyExpired(env, now);
  const targets = await env.DB.prepare(
    'SELECT ns, sub_key, data_bytes, file_bytes FROM accounts WHERE purge_requested = 1 LIMIT ?1',
  )
    .bind(ACCOUNTS_PER_RUN)
    .all<Target>();

  let purged = 0;
  let pending = 0;
  for (const t of targets.results) {
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
  return { purged, pending, marked };
}
