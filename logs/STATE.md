# STATE.md - Trạng thái project

> Agent đọc file này ở đầu mỗi phiên và cập nhật ở cuối mỗi phiên.
> Quy trình: `.standards/docs/AGENT_PROTOCOL.md`.

## Hàng đợi task (làm từ trên xuống)

- ⛔ **ĐÃ NGỪNG 25/11/2026** (bộ quy ước v7.0.0, phiếu `20261125-SYN1`): không deploy, không phát triển tiếp; repo
  được lưu trữ (archive) với sự cho phép của chủ dự án. Đồng bộ thiết bị chuyển sang `tsudev-org/tsulink`. Các phiếu
  bản sao còn lại trong `logs/handover/` (AV1, SEC1, QR1, INT1, SEC2, UI2, SDB1) KHÔNG áp dụng nữa.

## Đang thực hiện

| Task | Agent | Bắt đầu |
| --- | --- | --- |

## Đã hoàn thành (mới nhất trên cùng)

- 26/11/2026 - SYN1: biểu ngữ ngừng trong README, cập nhật STATE, rồi archive repo (điều phối projects-82).

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
