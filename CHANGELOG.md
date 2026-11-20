# Nhật ký thay đổi

Theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/) và SemVer.

## [Chưa phát hành]

### Thêm

- ADR-0003: định dạng bản mã `TS 01` (secretstream XChaCha20-Poly1305, khối 64 KiB, `sodium_pad`, AAD gắn
  không gian tên + loại + id), khoá Argon2id13 (NFKC, 3 lượt / 64 MiB, sàn 2 / 19 MiB, trần 16 / 1 GiB) + `crypto_kdf`.
- Thư viện máy khách TypeScript `@tsudev/sync` 0.1.0 (`clients/ts`) và Dart `tsusync` 0.1.0 (`clients/dart`): mã hoá,
  máy khách HTTP (402 `pro_required`, `stale` thử lại một lần, DPoP qua hàm ký), `SyncSession`.
- `conformance/vectors-v1.json` + bộ kiểm libsodium độc lập (Python ctypes); CI kiểm cả bản mã TypeScript và Dart vừa tạo.
- PRO-D3: crate Rust `tsusync` 0.1.0 (`clients/rust`, `dryoc` + `unicode-normalization`) - phần mã hoá cùng API/ngữ nghĩa
  với TypeScript, qua đủ 36 ca `vectors-v1.json`; job CI `client-rust` (fmt, clippy, test, bản mã Rust vừa tạo mở bằng
  libsodium C).
- PRO-D3: .NET `Tsudev.Sync` 0.1.0 (`clients/dotnet`, P/Invoke libsodium C) - cùng API/ngữ nghĩa, qua đủ 36 ca; job CI
  `client-dotnet` (khôi phục `--locked-mode`, `dotnet format`, xUnit, bản mã .NET vừa tạo mở bằng libsodium C).

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
