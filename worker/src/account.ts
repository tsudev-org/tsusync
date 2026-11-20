import { GRACE_MS, globalBudget, intVar, quotaFor } from './config';
import { encryptSub, randomToken } from './crypto';
import type { Caller, Env } from './env';
import { ApiError } from './errors';

export interface AccountRow {
  ns: string;
  sub_key: string;
  rev: number;
  data_bytes: number;
  file_bytes: number;
  pro_until: number;
  pro_iat: number;
  lock: string;
  purge_requested: number;
  created_at: number;
  seen_at: number;
  sub_enc: ArrayBuffer | null;
  purge_checked_at: number;
}

const SEEN_REFRESH_MS = 24 * 3600 * 1000;

export const isPro = (c: Caller, now = Date.now()) => c.proUntil > now;
/** Kéo/tải/xuất: còn Pro, hoặc hết Pro chưa quá 90 ngày (PRODUCT_POLICY 7.2). */
export const canRead = (c: Caller, now = Date.now()) => c.proUntil > 0 && c.proUntil + GRACE_MS > now;
/** Mốc xoá dữ liệu trên máy chủ (mili giây) - 0 khi chưa từng có Pro. */
export const purgeAt = (proUntil: number) => (proUntil > 0 ? proUntil + GRACE_MS : 0);

export function proRequired(reason: 'no_pro' | 'grace_expired') {
  const message =
    reason === 'grace_expired'
      ? 'Gói TsuDEV Pro đã hết hạn quá 90 ngày nên dữ liệu đám mây không còn. Dữ liệu trên thiết bị vẫn đầy đủ.'
      : 'Đồng bộ và sao lưu đám mây cần TsuDEV Pro. Dữ liệu vẫn lưu đầy đủ trên thiết bị này.';
  return new ApiError(402, 'pro_required', message, { reason });
}

export function assertCanWrite(c: Caller) {
  if (!isPro(c)) throw proRequired('no_pro');
}

export function assertCanRead(c: Caller) {
  if (!canRead(c)) throw proRequired(c.proUntil > 0 ? 'grace_expired' : 'no_pro');
}

const purging = () =>
  new ApiError(409, 'purge_in_progress', 'Dữ liệu đám mây của tài khoản đang được xoá theo yêu cầu. Hãy thử lại sau ít phút.', undefined, {
    'Retry-After': '300',
  });

export async function getAccount(env: Env, c: Caller): Promise<AccountRow | null> {
  return env.DB.prepare('SELECT * FROM accounts WHERE ns = ? AND sub_key = ?').bind(c.ns, c.subKey).first<AccountRow>();
}

/**
 * Đọc (tạo nếu chưa có) tài khoản và cập nhật `pro_until` từ JWS mới nhất. Chỉ ghi D1 khi giá trị đổi hoặc
 * `seen_at` cũ hơn 24 giờ - giữ số dòng ghi/ngày thấp (D1 Free: 100.000 dòng/ngày).
 */
export async function loadAccount(env: Env, c: Caller, opts: { create: boolean; allowPurging?: boolean }): Promise<AccountRow | null> {
  const now = Date.now();
  let a = await getAccount(env, c);
  if (!a) {
    if (!opts.create) return null;
    await env.DB.prepare(
      `INSERT INTO accounts (ns, sub_key, pro_until, pro_iat, lock, created_at, seen_at, sub_enc) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
       ON CONFLICT (ns, sub_key) DO NOTHING`,
    )
      .bind(c.ns, c.subKey, c.proUntil, c.iat, randomToken(), now, await encryptSub(env.SUB_ENC_KEY, c.ns, c.sub))
      .run();
    a = await getAccount(env, c);
    if (!a) throw new ApiError(503, 'unavailable', 'Máy chủ đồng bộ tạm bận. Hãy thử lại sau.');
  } else {
    const newer = c.iat > a.pro_iat && c.proUntil !== a.pro_until;
    if (!a.sub_enc && env.SUB_ENC_KEY) {
      // Tài khoản tạo trước khi có SUB_ENC_KEY (hoặc trước v0.2.0): bổ sung để xoá có xác minh được.
      const subEnc = await encryptSub(env.SUB_ENC_KEY, c.ns, c.sub);
      if (subEnc) {
        await env.DB.prepare('UPDATE accounts SET sub_enc = ?3 WHERE ns = ?1 AND sub_key = ?2 AND sub_enc IS NULL').bind(c.ns, c.subKey, subEnc).run();
      }
    }
    if (newer || a.seen_at < now - SEEN_REFRESH_MS) {
      // JWS cũ hơn bản đã biết không được hạ/ nâng pro_until (chống phát lại JWS cũ).
      await env.DB.prepare(
        `UPDATE accounts SET pro_until = CASE WHEN ?3 > pro_iat THEN ?4 ELSE pro_until END,
           pro_iat = MAX(pro_iat, ?3), seen_at = ?5 WHERE ns = ?1 AND sub_key = ?2`,
      )
        .bind(c.ns, c.subKey, c.iat, c.proUntil, now)
        .run();
      if (newer) a = { ...a, pro_until: c.proUntil, pro_iat: c.iat };
    }
  }
  if (a.purge_requested && !opts.allowPurging) throw purging();
  return a;
}

/** Giới hạn ghi theo tài khoản (cửa sổ cố định 1 phút trên D1). */
export async function rateLimitWrite(env: Env, c: Caller) {
  const limit = intVar(env.WRITE_RATE_PER_MIN, 120);
  const t = Date.now();
  const windowStart = t - (t % 60_000);
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (key, window_start, count) VALUES (?1, ?2, 1)
     ON CONFLICT (key) DO UPDATE SET count = CASE WHEN window_start = ?2 THEN count + 1 ELSE 1 END, window_start = ?2
     RETURNING count`,
  )
    .bind(`${c.ns}:${c.subKey}`, windowStart)
    .first<{ count: number }>();
  if ((row?.count ?? 0) > limit) {
    const retry = Math.max(1, Math.ceil((windowStart + 60_000 - t) / 1000));
    throw new ApiError(429, 'rate_limited', 'Thiết bị đồng bộ quá dày. Hãy thử lại sau ít giây.', undefined, { 'Retry-After': String(retry) });
  }
}

export function quotaExceeded(kind: 'data' | 'files', limit: number) {
  return new ApiError(413, 'quota_exceeded', 'Đã dùng hết hạn mức đám mây của gói TsuDEV Pro cho sản phẩm này.', { kind, limit });
}

/** Trần toàn dịch vụ: chạm ⇒ 507 và cảnh báo chủ dự án (không tự vượt hạn mức miễn phí, N7). */
export async function assertGlobalBudget(env: Env, kind: 'data' | 'files', delta: number) {
  if (delta <= 0) return;
  const t = await env.DB.prepare('SELECT data_bytes, file_bytes FROM totals WHERE id = 1').first<{ data_bytes: number; file_bytes: number }>();
  const budget = globalBudget(env);
  const used = kind === 'data' ? (t?.data_bytes ?? 0) : (t?.file_bytes ?? 0);
  const cap = kind === 'data' ? budget.data : budget.files;
  if (used + delta > cap) {
    console.warn('capacity_reached', kind);
    throw new ApiError(507, 'capacity_reached', 'Máy chủ đồng bộ tạm hết dung lượng. Dữ liệu vẫn an toàn trên máy; chủ dự án đã được báo.', { kind });
  }
}

export function accountView(env: Env, c: Caller, a: AccountRow | null) {
  const q = quotaFor(env, c.ns);
  const proUntil = a ? Math.max(a.pro_until, c.proUntil) : c.proUntil;
  return {
    namespace: c.ns,
    pro: isPro(c),
    pro_until: Math.floor(c.proUntil / 1000),
    read_until: Math.floor(purgeAt(proUntil) / 1000),
    rev: a?.rev ?? 0,
    quota: { data_bytes: a?.data_bytes ?? 0, data_limit: q.data, file_bytes: a?.file_bytes ?? 0, file_limit: q.files },
    purge_requested: !!a?.purge_requested,
  };
}
