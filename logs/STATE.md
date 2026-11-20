# STATE.md - Trạng thái project

> Agent đọc file này ở đầu mỗi phiên và cập nhật ở cuối mỗi phiên.
> Quy trình: `.standards/docs/AGENT_PROTOCOL.md`.

## Hàng đợi task (làm từ trên xuống)

- [ ] PRO-D2: thư viện TypeScript `@tsudev/sync` + Dart `tsusync` + vector đối chiếu (libsodium secretstream,
  Argon2id ≥ 64 MiB / 3 lượt, NFKC - cùng thông số qulythuchi ADR-0007).
- [ ] Deploy khi có sản phẩm dùng + chủ dự án duyệt (ADR-0001 mục 4) - KHÔNG tự làm.

## Đang thực hiện

| Task | Agent | Bắt đầu |
| --- | --- | --- |

## Đã hoàn thành (mới nhất trên cùng)

- 20/11/2026 - v0.1.0: ADR-0001 + Worker API v1 + migration D1 + 41 test Miniflare (phase PRO-D1 của phiên điều phối).

## Quyết định quan trọng

- 20/11/2026 - Workers + D1 + R2, không gian tên = `aud`, xác thực bằng JWS quyền lợi - `docs/adr/0001-kien-truc-tsudev-sync.md`.

## Sự cố bảo mật

> Ghi theo `.standards/docs/SECURITY_BASELINE.md` mục 9. Để trống nếu chưa có.

- (chưa có)
