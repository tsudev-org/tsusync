/** Binding + biến của Worker (wrangler.jsonc). Không có secret: Worker chỉ KIỂM chữ ký, không ký gì. */
export interface Env {
  DB: D1Database;
  FILES: R2Bucket;
  /** Issuer OIDC của tsudev.com; JWKS lấy qua discovery của issuer này. */
  OIDC_ISSUER: string;
  /** Danh sách client_id được phép (phân cách bằng dấu phẩy). `aud` của JWS = không gian tên. */
  NAMESPACES: string;
  /** Hạn mức riêng theo không gian tên (ADR của sản phẩm), JSON: {"<ns>": {"data_mib": 200, "files_mib": 1024}}. */
  QUOTAS?: string;
  /** Trần dung lượng toàn dịch vụ (MiB) - đặt dưới hạn mức miễn phí D1/R2 (ADR-0001 mục 3.6). */
  GLOBAL_DATA_BUDGET_MIB: string;
  GLOBAL_FILE_BUDGET_MIB: string;
  /** Số lượt ghi tối đa mỗi tài khoản mỗi phút. */
  WRITE_RATE_PER_MIN: string;
  /**
   * Xoá tự động 90 ngày sau khi hết Pro: "verified" (mặc định) = chỉ xoá khi tsudev.com xác nhận qua kênh trạng thái
   * RP rằng tài khoản KHÔNG gia hạn; "off" = không tự xoá. Yêu cầu xoá của chính người dùng luôn chạy.
   */
  PURGE_MODE?: string;
  /** client_id của TsuDEV Sync tại tsudev.com (kênh RP, private_key_jwt). */
  RP_CLIENT_ID: string;
  /** `POST` kênh trạng thái quyền lợi (PRODUCT_POLICY 7.4) - cũng là `aud` của client assertion. */
  ENTITLEMENTS_STATUS_URL: string;
  /** Secret: khoá riêng EC P-256 (JWK JSON) ký client assertion. Thiếu ⇒ không xác minh được ⇒ không tự xoá. */
  RP_PRIVATE_JWK?: string;
  /** Secret: 32 byte base64url - AES-256-GCM mã hoá `sub` để hỏi lại tsudev.com trước khi xoá. */
  SUB_ENC_KEY?: string;
  /** "on" = bắt buộc JWS gắn khoá thiết bị (`cnf.jkt`) + bằng chứng DPoP (RFC 9449) cho mọi yêu cầu. */
  DPOP_REQUIRED?: string;
  /** Tỉ lệ yêu cầu chạy kèm lượt dọn (0-1, mặc định 0.01). */
  MAINTENANCE_SAMPLE?: string;
}

export interface Caller {
  ns: string;
  /** `sub` gốc - CHỈ giữ trong bộ nhớ của yêu cầu; D1 lưu `sub_key` (băm) + `sub_enc` (mã hoá). */
  sub: string;
  /** Thumbprint khoá thiết bị (RFC 7638) nếu JWS gắn khoá (`cnf.jkt`). */
  jkt: string | null;
  subKey: string;
  /** mili giây Unix; 0 = chưa từng có Pro. */
  proUntil: number;
  /** giây Unix (iat của JWS). */
  iat: number;
}

export interface AppEnv {
  Bindings: Env;
  Variables: { caller: Caller };
}
