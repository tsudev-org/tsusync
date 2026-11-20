import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { z } from 'zod';

import { assertCanRead, assertCanWrite, assertGlobalBudget, loadAccount, quotaExceeded, rateLimitWrite, type AccountRow } from './account';
import { requireCaller } from './auth';
import { ID_RE, MAX_BATCH, MAX_BATCH_BYTES, MAX_PULL, MAX_RECORD_BYTES, PULL_BYTES, PUSH_BODY_LIMIT, RECORD_OVERHEAD, quotaFor } from './config';
import { b64url, fromB64url, randomToken, sha256 } from './crypto';
import type { AppEnv, Caller, Env } from './env';
import { ApiError, badRequest } from './errors';

/**
 * Đồng bộ bản ghi (ADR-0001 mục 3.3-3.5). Máy chủ không đọc được nội dung: chỉ lưu bản mã, gán `rev` tăng dần theo
 * tài khoản + không gian tên, trả phần thay đổi sau một con trỏ `rev`. Ghi lặp lại cùng nội dung ⇒ `unchanged`.
 */

const itemIn = z.object({
  id: z.string().regex(ID_RE),
  /** null/thiếu = ghi đè (ai ghi sau thắng); số = chỉ ghi khi rev hiện tại khớp (0 = chưa tồn tại). */
  base_rev: z.number().int().min(0).nullable().optional(),
  deleted: z.boolean().optional(),
  /** base64url bản mã (secretstream của máy khách); bắt buộc khi không xoá. */
  payload: z.string().max(Math.ceil((MAX_RECORD_BYTES * 4) / 3) + 4).optional(),
});
const pushBody = z.object({ items: z.array(itemIn).min(1).max(MAX_BATCH) });

export type PushResult =
  | { id: string; status: 'applied' | 'unchanged'; rev: number }
  | { id: string; status: 'conflict'; rev: number }
  | { id: string; status: 'rejected'; reason: 'invalid_payload' | 'duplicate' };

interface Existing {
  id: string;
  rev: number;
  deleted: number;
  size: number;
  digest: string;
}

interface Planned {
  id: string;
  deleted: boolean;
  payload: Uint8Array | null;
  digest: string;
  size: number;
}

const MAX_ATTEMPTS = 4;

async function existingFor(env: Env, c: Caller, ids: string[]): Promise<Map<string, Existing>> {
  const out = new Map<string, Existing>();
  // D1: tối đa 100 tham số mỗi truy vấn ⇒ chia khối 90 id.
  for (let i = 0; i < ids.length; i += 90) {
    const chunk = ids.slice(i, i + 90);
    const rows = await env.DB.prepare(
      `SELECT id, rev, deleted, size, digest FROM records WHERE ns = ? AND sub_key = ? AND id IN (${chunk.map(() => '?').join(',')})`,
    )
      .bind(c.ns, c.subKey, ...chunk)
      .all<Existing>();
    for (const r of rows.results) out.set(r.id, r);
  }
  return out;
}

export async function push(env: Env, c: Caller, items: z.infer<typeof itemIn>[]): Promise<{ results: PushResult[]; rev: number }> {
  // 1. Kiểm khung từng mục (không cần D1).
  const seen = new Set<string>();
  const valid: (Planned & { baseRev: number | null; index: number })[] = [];
  const results: (PushResult | null)[] = items.map(() => null);
  let batchBytes = 0;
  for (const [index, it] of items.entries()) {
    if (seen.has(it.id)) {
      results[index] = { id: it.id, status: 'rejected', reason: 'duplicate' };
      continue;
    }
    seen.add(it.id);
    const deleted = it.deleted === true;
    let payload: Uint8Array | null = null;
    if (deleted) {
      if (it.payload !== undefined && it.payload !== '') {
        results[index] = { id: it.id, status: 'rejected', reason: 'invalid_payload' };
        continue;
      }
    } else {
      payload = it.payload ? fromB64url(it.payload) : null;
      if (!payload || payload.length === 0 || payload.length > MAX_RECORD_BYTES) {
        results[index] = { id: it.id, status: 'rejected', reason: 'invalid_payload' };
        continue;
      }
    }
    batchBytes += payload?.length ?? 0;
    const digest = deleted ? 'deleted' : b64url(await sha256(payload ?? new Uint8Array()));
    const size = (payload?.length ?? 0) + it.id.length + RECORD_OVERHEAD;
    valid.push({ id: it.id, deleted, payload, digest, size, baseRev: it.base_rev ?? null, index });
  }
  if (batchBytes > MAX_BATCH_BYTES) throw new ApiError(413, 'batch_too_large', 'Lô đồng bộ quá lớn. Hãy chia nhỏ.');

  const quota = quotaFor(env, c.ns).data;
  for (let attempt = 1; ; attempt++) {
    const acc = (await loadAccount(env, c, { create: true })) as AccountRow;
    const existing = await existingFor(env, c, valid.map((v) => v.id));
    const now = Date.now();

    // 2. Quyết định từng mục dựa trên trạng thái vừa đọc.
    let rev = acc.rev;
    let delta = 0;
    const writes: (Planned & { rev: number })[] = [];
    const decided: { index: number; result: PushResult }[] = [];
    for (const v of valid) {
      const ex = existing.get(v.id);
      if (ex && ex.digest === v.digest && !!ex.deleted === v.deleted) {
        decided.push({ index: v.index, result: { id: v.id, status: 'unchanged', rev: ex.rev } });
        continue;
      }
      if (v.baseRev !== null && v.baseRev !== (ex?.rev ?? 0)) {
        decided.push({ index: v.index, result: { id: v.id, status: 'conflict', rev: ex?.rev ?? 0 } });
        continue;
      }
      // Xoá thứ chưa từng có trên máy chủ vẫn ghi bia mộ để thiết bị khác cũng xoá.
      rev += 1;
      delta += v.size - (ex?.size ?? 0);
      writes.push({ ...v, rev });
      decided.push({ index: v.index, result: { id: v.id, status: 'applied', rev } });
    }

    if (writes.length > 0) {
      // 3. Hạn mức cả lô (không cắt âm thầm: vượt ⇒ 413, không ghi gì).
      if (acc.data_bytes + delta > quota) throw quotaExceeded('data', quota);
      await assertGlobalBudget(env, 'data', delta);

      // 4. Ghi một batch D1 (giao dịch). Thẻ `lock` bảo đảm chỉ ghi khi không ai ghi chen giữa bước 1 và 4.
      const newLock = randomToken();
      const guard = 'EXISTS (SELECT 1 FROM accounts WHERE ns = ?1 AND sub_key = ?2 AND lock = ?3)';
      const stmts: D1PreparedStatement[] = [
        env.DB.prepare(
          'UPDATE accounts SET rev = ?4, data_bytes = data_bytes + ?5, lock = ?3 WHERE ns = ?1 AND sub_key = ?2 AND lock = ?6',
        ).bind(c.ns, c.subKey, newLock, rev, delta, acc.lock),
        env.DB.prepare(`UPDATE totals SET data_bytes = data_bytes + ?4 WHERE id = 1 AND ${guard}`).bind(c.ns, c.subKey, newLock, delta),
      ];
      for (const w of writes) {
        stmts.push(
          env.DB.prepare(
            `INSERT INTO records (ns, sub_key, id, rev, deleted, size, digest, payload, updated_at)
             SELECT ?1, ?2, ?4, ?5, ?6, ?7, ?8, ?9, ?10 WHERE ${guard}
             ON CONFLICT (ns, sub_key, id) DO UPDATE SET rev = excluded.rev, deleted = excluded.deleted, size = excluded.size,
               digest = excluded.digest, payload = excluded.payload, updated_at = excluded.updated_at`,
          ).bind(c.ns, c.subKey, newLock, w.id, w.rev, w.deleted ? 1 : 0, w.size, w.digest, w.payload, now),
        );
      }
      const out = await env.DB.batch(stmts);
      if ((out[0]?.meta.changes ?? 0) !== 1) {
        if (attempt >= MAX_ATTEMPTS) {
          throw new ApiError(503, 'busy', 'Nhiều thiết bị đang đồng bộ cùng lúc. Hãy thử lại.', undefined, { 'Retry-After': '2' });
        }
        continue;
      }
    }

    for (const d of decided) results[d.index] = d.result;
    return { results: results as PushResult[], rev };
  }
}

interface PullRow {
  id: string;
  rev: number;
  deleted: number;
  payload: ArrayBuffer | null;
}

export async function pull(env: Env, c: Caller, since: number, limit: number) {
  const rows = await env.DB.prepare(
    'SELECT id, rev, deleted, payload FROM records WHERE ns = ? AND sub_key = ? AND rev > ? ORDER BY rev LIMIT ?',
  )
    .bind(c.ns, c.subKey, since, limit + 1)
    .all<PullRow>();
  const items: { id: string; rev: number; deleted: boolean; payload?: string }[] = [];
  let bytes = 0;
  let more = rows.results.length > limit;
  for (const r of rows.results.slice(0, limit)) {
    const size = r.payload ? r.payload.byteLength : 0;
    if (items.length > 0 && bytes + size > PULL_BYTES) {
      more = true;
      break;
    }
    bytes += size;
    items.push(r.deleted ? { id: r.id, rev: r.rev, deleted: true } : { id: r.id, rev: r.rev, deleted: false, payload: b64url(new Uint8Array(r.payload ?? new ArrayBuffer(0))) });
  }
  const next = items.length > 0 ? (items[items.length - 1]?.rev ?? since) : since;
  return { items, next, more };
}

export const recordRoutes = new Hono<AppEnv>();

recordRoutes.get('/v1/records', requireCaller, async (c) => {
  const caller = c.get('caller');
  assertCanRead(caller);
  const sinceRaw = c.req.query('since') ?? '0';
  const limitRaw = c.req.query('limit') ?? '200';
  if (!/^\d{1,15}$/.test(sinceRaw) || !/^\d{1,4}$/.test(limitRaw)) throw badRequest();
  const limit = Math.min(Math.max(Number(limitRaw), 1), MAX_PULL);
  await loadAccount(c.env, caller, { create: false });
  return c.json(await pull(c.env, caller, Number(sinceRaw), limit));
});

recordRoutes.post(
  '/v1/records',
  bodyLimit({
    maxSize: PUSH_BODY_LIMIT,
    onError: () => {
      throw new ApiError(413, 'payload_too_large', 'Lô đồng bộ quá lớn. Hãy chia nhỏ.');
    },
  }),
  requireCaller,
  async (c) => {
    const caller = c.get('caller');
    assertCanWrite(caller);
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw badRequest();
    }
    const parsed = pushBody.safeParse(body);
    if (!parsed.success) throw badRequest();
    await rateLimitWrite(c.env, caller);
    return c.json(await push(c.env, caller, parsed.data.items));
  },
);
