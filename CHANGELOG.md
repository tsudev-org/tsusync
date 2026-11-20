# Nhật ký thay đổi

Theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/) và SemVer.

## [0.1.0] - 20/11/2026

### Thêm

- ADR-0001: kiến trúc TsuDEV Sync (Workers + D1 + R2), hạn mức miễn phí Cloudflare đo 20/11/2026.
- Worker API v1: xác thực bằng JWS quyền lợi ES256 (JWKS qua discovery), `402 pro_required`, đồng bộ bản ghi theo con
  trỏ `rev` (idempotent, `base_rev` chống ghi đè), tệp bản mã trên R2 có kiểm SHA-256, hạn mức 100 MiB + 1 GiB, trần
  toàn dịch vụ `507`, giới hạn tần suất `429`, xoá theo yêu cầu và xoá 90 ngày sau khi hết Pro (mặc định tắt).
- Migration D1 `0001_init.sql`; 41 test Miniflare (D1/R2 giả lập).
