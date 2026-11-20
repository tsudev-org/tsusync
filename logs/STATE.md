# STATE.md - Trạng thái project

> Agent đọc file này ở đầu mỗi phiên và cập nhật ở cuối mỗi phiên.
> Quy trình: `.standards/docs/AGENT_PROTOCOL.md`.

## Hàng đợi task (làm từ trên xuống)

- [ ] PRO-D3: Rust crate `tsusync` + .NET `TsuSync` qua `conformance/vectors-v1.json` (ADR-0003).
- [ ] Chờ tsudev.com triển khai kênh trạng thái + DPoP (phiếu `tsudev/logs/handover/20261120-PRO2_*`), rồi
  `DPOP_REQUIRED = "on"` khi mọi máy khách đã ký DPoP (ADR-0002 mục 3.2).
- [ ] Deploy khi có sản phẩm dùng + chủ dự án duyệt (ADR-0001 mục 4) - KHÔNG tự làm.

## Đang thực hiện

| Task | Agent | Bắt đầu |
| --- | --- | --- |

## Đã hoàn thành (mới nhất trên cùng)

- 20/11/2026 - PRO-D2: ADR-0003 (định dạng `TS 01`), `@tsudev/sync` 0.1.0 (53 test) + Dart `tsusync` 0.1.0, vector
  `conformance/vectors-v1.json` (36 ca) kiểm thêm bằng libsodium C độc lập. (`logs/LOCKS.md` chỉ-đọc nên không khoá
  được file - đã ghi phạm vi vào PR.)

- 20/11/2026 - v0.2.0: ADR-0002 (xoá có xác minh, JWS ≤ 24 giờ, DPoP), vitest-plugin + vitest 5; 51 test.
- 20/11/2026 - v0.1.0: ADR-0001 + Worker API v1 + migration D1 + 41 test Miniflare (phase PRO-D1 của phiên điều phối).

## Quyết định quan trọng

- 20/11/2026 - Định dạng bản mã máy khách `TS 01` + vector chéo - `docs/adr/0003-ma-hoa-may-khach-dinh-dang-ts01.md`.
- 20/11/2026 - Xoá có xác minh + JWS tươi + DPoP - `docs/adr/0002-xoa-co-xac-minh-jws-tuoi-dpop.md`.
- 20/11/2026 - Workers + D1 + R2, không gian tên = `aud`, xác thực bằng JWS quyền lợi - `docs/adr/0001-kien-truc-tsudev-sync.md`.

## Sự cố bảo mật

> Ghi theo `.standards/docs/SECURITY_BASELINE.md` mục 9. Để trống nếu chưa có.

- (chưa có)
