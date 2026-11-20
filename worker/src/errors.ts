import type { Context } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';

/**
 * Lỗi API: `error` là mã máy đọc (hợp đồng PRODUCT_POLICY 7.4: 402 ⇒ `{"error":"pro_required"}`), `message` là câu
 * cố định tiếng Việt - KHÔNG BAO GIỜ nhúng dữ liệu người dùng.
 */
export class ApiError extends Error {
  constructor(
    readonly status: ContentfulStatusCode,
    readonly code: string,
    message: string,
    readonly extra?: Record<string, string | number>,
    readonly headers?: Record<string, string>,
  ) {
    super(message);
  }
}

export function errorResponse(c: Context, err: ApiError) {
  for (const [k, v] of Object.entries(err.headers ?? {})) c.header(k, v);
  return c.json({ error: err.code, message: err.message, ...err.extra }, err.status);
}

export const badRequest = (message = 'Yêu cầu không hợp lệ.') => new ApiError(400, 'invalid_request', message);
export const unauthorized = () =>
  new ApiError(401, 'invalid_token', 'Phiên quyền lợi không hợp lệ hoặc đã hết hạn. Hãy lấy lại từ tsudev.com.', undefined, {
    'WWW-Authenticate': 'Bearer error="invalid_token"',
  });
