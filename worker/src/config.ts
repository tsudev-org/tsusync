import type { Env } from './env';

export const MIB = 1024 * 1024;
/** Hạn mức Pro mặc định mỗi tài khoản mỗi sản phẩm (PRODUCT_POLICY 7.5, FREE_TIER_STACK 3.1). */
export const DEFAULT_DATA_QUOTA = 100 * MIB;
export const DEFAULT_FILE_QUOTA = 1024 * MIB;
/** Pro hết hạn: còn kéo + xuất 90 ngày rồi xoá (PRODUCT_POLICY 7.2). */
export const GRACE_MS = 90 * 24 * 3600 * 1000;

/** Một bản ghi tối đa 64 KiB bản mã; nội dung lớn hơn ⇒ dùng tệp. */
export const MAX_RECORD_BYTES = 64 * 1024;
/** Một lô đẩy: tối đa 100 bản ghi và 2 MiB bản mã (D1: 1 batch = 1 truy vấn, giữ dưới giới hạn yêu cầu). */
export const MAX_BATCH = 100;
export const MAX_BATCH_BYTES = 2 * MIB;
export const PUSH_BODY_LIMIT = 3 * MIB;
/** Một tệp tối đa 64 MiB (Worker Free: thân yêu cầu 100 MB, 128 MB bộ nhớ) - lớn hơn ⇒ máy khách chia khối. */
export const MAX_FILE_BYTES = 64 * MIB;
/** Kéo: tối đa 500 mục và ~4 MiB bản mã mỗi trang. */
export const MAX_PULL = 500;
export const PULL_BYTES = 4 * MIB;
/** Chi phí cố định mỗi bản ghi (khoá, rev, chỉ mục) để bia mộ không "miễn phí". */
export const RECORD_OVERHEAD = 64;

/** Định danh mờ do máy khách chọn: 1-128 ký tự an toàn URL. */
export const ID_RE = /^[A-Za-z0-9._~:-]{1,128}$/;
/** base64url(SHA-256) không đệm. */
export const DIGEST_RE = /^[A-Za-z0-9_-]{43}$/;
export const INSTALLATION_RE = /^[A-Za-z0-9_-]{22}$/;

export function namespaces(env: Env): Set<string> {
  return new Set(
    env.NAMESPACES.split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

export interface Quota {
  data: number;
  files: number;
}

export function quotaFor(env: Env, ns: string): Quota {
  const q: Quota = { data: DEFAULT_DATA_QUOTA, files: DEFAULT_FILE_QUOTA };
  if (!env.QUOTAS) return q;
  try {
    const all = JSON.parse(env.QUOTAS) as Record<string, { data_mib?: unknown; files_mib?: unknown } | undefined>;
    const o = all[ns];
    if (typeof o?.data_mib === 'number' && o.data_mib > 0) q.data = Math.floor(o.data_mib * MIB);
    if (typeof o?.files_mib === 'number' && o.files_mib > 0) q.files = Math.floor(o.files_mib * MIB);
  } catch {
    // Cấu hình hỏng ⇒ dùng mặc định (không nới hạn mức vì lỗi gõ).
  }
  return q;
}

export function intVar(v: string | undefined, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Tỉ lệ yêu cầu kéo theo một lượt dọn (mặc định 1%; test đặt 0 để kết quả tất định). */
export function maintenanceSample(env: Env): number {
  const n = Number(env.MAINTENANCE_SAMPLE ?? '0.01');
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : 0.01;
}

export const globalBudget = (env: Env) => ({
  data: intVar(env.GLOBAL_DATA_BUDGET_MIB, 400) * MIB,
  files: intVar(env.GLOBAL_FILE_BUDGET_MIB, 8192) * MIB,
});
