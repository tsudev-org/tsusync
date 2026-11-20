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
/**
 * 401: `reason` cho máy khách biết nên làm gì - `stale` (JWS cũ hơn 24 giờ: lấy JWS mới rồi thử lại),
 * `dpop_required` / `invalid_dpop_proof` (thiếu/sai bằng chứng khoá thiết bị), mặc định `invalid`.
 */
export const unauthorized = (reason: 'invalid' | 'stale' | 'dpop_required' | 'invalid_dpop_proof' = 'invalid') =>
  new ApiError(401, 'invalid_token', 'Phiên quyền lợi không hợp lệ hoặc đã hết hạn. Hãy lấy lại từ tsudev.com.', { reason }, {
    'WWW-Authenticate': reason.includes('dpop') ? `DPoP error="${reason === 'dpop_required' ? 'invalid_token' : 'invalid_dpop_proof'}", algs="ES256"` : 'Bearer error="invalid_token"',
  });
