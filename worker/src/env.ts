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
  /** "on" mới tự xoá dữ liệu 90 ngày sau khi hết Pro (yêu cầu xoá của chính người dùng luôn chạy). */
  PURGE_ENABLED: string;
  /** Tỉ lệ yêu cầu chạy kèm lượt dọn (0-1, mặc định 0.01). */
  MAINTENANCE_SAMPLE?: string;
}

export interface Caller {
  ns: string;
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
