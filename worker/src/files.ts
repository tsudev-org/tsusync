import { Hono } from 'hono';

import { assertCanRead, assertCanWrite, assertGlobalBudget, loadAccount, quotaExceeded, rateLimitWrite, type AccountRow } from './account';
import { requireCaller } from './auth';
import { DIGEST_RE, ID_RE, MAX_FILE_BYTES, MAX_PULL, quotaFor } from './config';
import { fromB64url, hex, randomToken } from './crypto';
import type { AppEnv, Caller, Env } from './env';
import { ApiError, badRequest } from './errors';

/**
 * Tệp bản mã trên R2 (ADR-0001 mục 3.4). Khoá R2: `<ns>/<sub_key>/<id>`. Máy khách gửi `X-Tsu-Digest` =
 * base64url(SHA-256 bản mã); R2 kiểm lại khi ghi nên tệp hỏng giữa đường bị từ chối. Siêu dữ liệu + `rev` ở D1,
 * dùng chung con trỏ `rev` với bản ghi để máy khách kéo danh sách thay đổi.
 */

interface FileRow {
  id: string;
  rev: number;
  deleted: number;
  size: number;
  digest: string;
}

const MAX_ATTEMPTS = 4;
export const objectKey = (c: Pick<Caller, 'ns' | 'subKey'>, id: string) => `${c.ns}/${c.subKey}/${id}`;

const notFound = () => new ApiError(404, 'not_found', 'Không tìm thấy tệp.');
const busy = () => new ApiError(503, 'busy', 'Nhiều thiết bị đang đồng bộ cùng lúc. Hãy thử lại.', undefined, { 'Retry-After': '2' });

function fileId(raw: string): string {
  if (!ID_RE.test(raw)) throw badRequest();
  return raw;
}

async function fileRow(env: Env, c: Caller, id: string) {
  return env.DB.prepare('SELECT id, rev, deleted, size, digest FROM files WHERE ns = ? AND sub_key = ? AND id = ?')
    .bind(c.ns, c.subKey, id)
    .first<FileRow>();
}

/** Ghi siêu dữ liệu tệp + cộng dồn dung lượng trong một batch có thẻ `lock` (xem records.ts). */
async function commitFile(env: Env, c: Caller, id: string, next: { deleted: boolean; size: number; digest: string }) {
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const acc = (await loadAccount(env, c, { create: true, allowPurging: false })) as AccountRow;
    const ex = await fileRow(env, c, id);
    const delta = next.size - (ex && !ex.deleted ? ex.size : 0);
    const rev = acc.rev + 1;
    const newLock = randomToken();
    const guard = 'EXISTS (SELECT 1 FROM accounts WHERE ns = ?1 AND sub_key = ?2 AND lock = ?3)';
    const out = await env.DB.batch([
      env.DB.prepare('UPDATE accounts SET rev = ?4, file_bytes = MAX(0, file_bytes + ?5), lock = ?3 WHERE ns = ?1 AND sub_key = ?2 AND lock = ?6').bind(
        c.ns,
        c.subKey,
        newLock,
        rev,
        delta,
        acc.lock,
      ),
      env.DB.prepare(`UPDATE totals SET file_bytes = MAX(0, file_bytes + ?4) WHERE id = 1 AND ${guard}`).bind(c.ns, c.subKey, newLock, delta),
      env.DB.prepare(
        `INSERT INTO files (ns, sub_key, id, rev, deleted, size, digest, updated_at)
         SELECT ?1, ?2, ?4, ?5, ?6, ?7, ?8, ?9 WHERE ${guard}
         ON CONFLICT (ns, sub_key, id) DO UPDATE SET rev = excluded.rev, deleted = excluded.deleted, size = excluded.size,
           digest = excluded.digest, updated_at = excluded.updated_at`,
      ).bind(c.ns, c.subKey, newLock, id, rev, next.deleted ? 1 : 0, next.size, next.digest, Date.now()),
    ]);
    if ((out[0]?.meta.changes ?? 0) === 1) return rev;
  }
  throw busy();
}

export const fileRoutes = new Hono<AppEnv>();

fileRoutes.get('/v1/files', requireCaller, async (c) => {
  const caller = c.get('caller');
  assertCanRead(caller);
  const sinceRaw = c.req.query('since') ?? '0';
  const limitRaw = c.req.query('limit') ?? '200';
  if (!/^\d{1,15}$/.test(sinceRaw) || !/^\d{1,4}$/.test(limitRaw)) throw badRequest();
  const limit = Math.min(Math.max(Number(limitRaw), 1), MAX_PULL);
  await loadAccount(c.env, caller, { create: false });
  const rows = await c.env.DB.prepare(
    'SELECT id, rev, deleted, size, digest FROM files WHERE ns = ? AND sub_key = ? AND rev > ? ORDER BY rev LIMIT ?',
  )
    .bind(caller.ns, caller.subKey, Number(sinceRaw), limit + 1)
    .all<FileRow>();
  const page = rows.results.slice(0, limit);
  return c.json({
    items: page.map((r) => (r.deleted ? { id: r.id, rev: r.rev, deleted: true } : { id: r.id, rev: r.rev, deleted: false, size: r.size, digest: r.digest })),
    next: page.length > 0 ? (page[page.length - 1]?.rev ?? Number(sinceRaw)) : Number(sinceRaw),
    more: rows.results.length > limit,
  });
});

fileRoutes.put('/v1/files/:id', requireCaller, async (c) => {
  const caller = c.get('caller');
  assertCanWrite(caller);
  const id = fileId(c.req.param('id'));
  const lenRaw = c.req.header('Content-Length');
  if (!lenRaw || !/^\d{1,12}$/.test(lenRaw)) throw new ApiError(411, 'length_required', 'Thiếu độ dài tệp.');
  const size = Number(lenRaw);
  if (size === 0) throw badRequest('Tệp rỗng.');
  if (size > MAX_FILE_BYTES) throw new ApiError(413, 'file_too_large', 'Tệp quá lớn cho một lần tải. Hãy chia khối.', { limit: MAX_FILE_BYTES });
  const digest = c.req.header('X-Tsu-Digest') ?? '';
  const digestBytes = DIGEST_RE.test(digest) ? fromB64url(digest) : null;
  if (!digestBytes) throw badRequest('Thiếu hoặc sai X-Tsu-Digest.');
  if (!c.req.raw.body) throw badRequest('Tệp rỗng.');

  await rateLimitWrite(c.env, caller);
  const acc = (await loadAccount(c.env, caller, { create: true })) as AccountRow;
  const ex = await fileRow(c.env, caller, id);
  if (ex && !ex.deleted && ex.digest === digest && ex.size === size) {
    await c.req.raw.body.cancel();
    return c.json({ id, status: 'unchanged', rev: ex.rev });
  }
  const delta = size - (ex && !ex.deleted ? ex.size : 0);
  const quota = quotaFor(c.env, caller.ns).files;
  if (acc.file_bytes + delta > quota) throw quotaExceeded('files', quota);
  await assertGlobalBudget(c.env, 'files', delta);

  try {
    await c.env.FILES.put(objectKey(caller, id), c.req.raw.body, {
      sha256: hex(digestBytes),
      customMetadata: { digest },
      httpMetadata: { contentType: 'application/octet-stream' },
    });
  } catch {
    throw new ApiError(400, 'digest_mismatch', 'Tệp tải lên không khớp mã kiểm. Hãy tải lại.');
  }
  const rev = await commitFile(c.env, caller, id, { deleted: false, size, digest });
  return c.json({ id, status: 'applied', rev }, ex ? 200 : 201);
});

fileRoutes.get('/v1/files/:id', requireCaller, async (c) => {
  const caller = c.get('caller');
  assertCanRead(caller);
  const id = fileId(c.req.param('id'));
  await loadAccount(c.env, caller, { create: false });
  const row = await fileRow(c.env, caller, id);
  if (!row || row.deleted) throw notFound();
  const obj = await c.env.FILES.get(objectKey(caller, id));
  if (!obj) throw notFound();
  return new Response(obj.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(obj.size),
      'X-Tsu-Digest': obj.customMetadata?.digest ?? row.digest,
      'Cache-Control': 'no-store',
    },
  });
});

/** Xoá được cả khi Pro đã hết hạn (trong 90 ngày) - người dùng luôn được giảm dữ liệu của mình. */
fileRoutes.delete('/v1/files/:id', requireCaller, async (c) => {
  const caller = c.get('caller');
  assertCanRead(caller);
  const id = fileId(c.req.param('id'));
  await rateLimitWrite(c.env, caller);
  const row = await fileRow(c.env, caller, id);
  if (!row || row.deleted) return c.json({ id, status: 'unchanged', rev: row?.rev ?? 0 });
  await c.env.FILES.delete(objectKey(caller, id));
  const rev = await commitFile(c.env, caller, id, { deleted: true, size: 0, digest: 'deleted' });
  return c.json({ id, status: 'applied', rev });
});
