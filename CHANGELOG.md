# Nhật ký thay đổi

Theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/) và SemVer.

## [0.2.0] - 20/11/2026

### Thêm

- ADR-0002. Xoá 90 ngày sau khi hết Pro **có xác minh**: hỏi kênh trạng thái `POST /api/rp/entitlements/status` của
  tsudev.com (client assertion `private_key_jwt`) - đã gia hạn ⇒ giữ dữ liệu + cập nhật `pro_until`; lỗi/không rõ ⇒
  hoãn. `PURGE_MODE` (`verified` | `off`) thay `PURGE_ENABLED`. `sub` lưu dạng AES-256-GCM (`sub_enc`), migration `0002`.
- DPoP (RFC 9449) cho JWS gắn khoá thiết bị (`cnf.jkt`), cờ `DPOP_REQUIRED`.

### Đổi

- JWS quyền lợi phải tươi: `iat` ≤ 24 giờ, cũ hơn ⇒ `401 reason: "stale"`. Mọi 401 có `reason`.
- Bộ test chuyển `@cloudflare/vitest-plugin` 1.8.5 + vitest 5.1; `wrangler.test.jsonc` dùng cùng `compatibility_date`
  01/11/2026 với bản chạy thật; TypeScript 6.0.3 (Dependabot bỏ qua ≥ 6.1 tới khi `typescript-eslint` hỗ trợ). 51 test.

## [0.1.0] - 20/11/2026

### Thêm

- ADR-0001: kiến trúc TsuDEV Sync (Workers + D1 + R2), hạn mức miễn phí Cloudflare đo 20/11/2026.
- Worker API v1: xác thực bằng JWS quyền lợi ES256 (JWKS qua discovery), `402 pro_required`, đồng bộ bản ghi theo con
  trỏ `rev` (idempotent, `base_rev` chống ghi đè), tệp bản mã trên R2 có kiểm SHA-256, hạn mức 100 MiB + 1 GiB, trần
  toàn dịch vụ `507`, giới hạn tần suất `429`, xoá theo yêu cầu và xoá 90 ngày sau khi hết Pro (mặc định tắt).
- Migration D1 `0001_init.sql`; 41 test Miniflare (D1/R2 giả lập).
