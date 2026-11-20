# 20261120-SDB1 - Yêu cầu từ sound-db: triển khai tsusync với `NAMESPACES` gồm `sounddb` + thẻ phát hành máy khách

- **Từ**: agent-sound (repo `tsudev-org/sound-db`, phiên `sound-db-32`), 20/11/2026 23:15.
- **Đến**: phiên tsusync kế tiếp + 👤 chủ dự án (duyệt deploy - ADR-0001 mục 4).
- **Trạng thái**: MỞ.
- **Ngữ cảnh**: sound-db ADR-0006 (ĐỀ XUẤT) chuyển đồng bộ đám mây sang tsusync, mã hoá đầu cuối `TS 01`. Kế hoạch +
  điều kiện P1-P4: `sound-db/logs/handover/20261120-E2E1_ke-hoach-chuyen-dong-bo-sang-tsusync.md`. Sound Db sẽ là
  sản phẩm ĐẦU TIÊN dùng tsusync thật.

## 1. Hiện trạng đo lúc 23:10 20/11/2026

- `sync.tsudev.com` không phân giải (curl HTTP 000); `worker/wrangler.jsonc` có `"NAMESPACES": ""`.
- Thẻ: `v0.1.0`, `v0.2.0` - cả hai TRƯỚC PRO-D2 (#4) nên không chứa `clients/dart` (`tsusync` 0.1.0) và
  `clients/ts` (`@tsudev/sync` 0.1.0). sound-db chỉ ghim được theo commit.

## 2. Việc yêu cầu

| # | Việc | Ai | Tương ứng E2E1 |
| --- | --- | --- | --- |
| R1 | Thẻ phát hành chứa `clients/dart` + `clients/ts` (vd. `v0.3.0`, ghi CHANGELOG) | phiên tsusync | P3 |
| R2 | Deploy theo README mục Triển khai: D1 `tsusync`, R2 `tsusync-files`, `NAMESPACES` gồm `sounddb`, `QUOTAS` mặc định, secret `RP_PRIVATE_JWK` + `SUB_ENC_KEY`, route `sync.tsudev.com` | 👤 duyệt + phiên tsusync | P2 |
| R3 | Khoá công khai RP của tsusync đăng ký ở tsudev.com (kênh trạng thái cho xoá có xác minh, ADR-0002) | phiên tsusync → phiếu sang tsudev | P2 |

Chỉ bắt đầu R2 sau khi 👤 duyệt (sound-db ADR-0006 đang ĐỀ XUẤT; tsusync ADR-0001 mục 4).

## 3. Hợp đồng sound-db sẽ dùng (để tsusync kiểm hộ nếu lệch)

- `aud` của JWS quyền lợi = `sounddb` (client OIDC `sounddb` trên tsudev.com).
- sound-db chỉ chuyển JWS cho app/web khi `iat` ≤ 12 giờ (biên an toàn so với ngưỡng 24 giờ `stale` của ADR-0002).
- Bản ghi: `id` = `s.<uuid>` (phiên đo) / `c.<uuid>` (hiệu chuẩn), payload `TS 01`; không dùng tệp (R2).
- Tham số khoá Argon2id lưu ở máy chủ Sound Db theo khuôn ADR-0003 mục 2.1-4.

## 4. Kết quả xử lý (phiên tsusync ghi)

-
