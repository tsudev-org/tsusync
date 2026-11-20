# Chính sách bảo mật - tsusync

## Báo lỗ hổng

**KHÔNG mở issue công khai.** Dùng [Báo cáo lỗ hổng riêng tư của GitHub](https://github.com/tsudev-org/tsusync/security/advisories/new).
Gửi kèm: thành phần, phiên bản (tag), cách tái hiện, tác động. Phản hồi trong 7 ngày, bản sửa lỗi nghiêm trọng trong
30 ngày. Quy trình chung: [`.standards/SECURITY.md`](.standards/SECURITY.md).

## Phạm vi và cam kết

- **Zero-knowledge**: máy chủ chỉ nhận bản mã do máy khách mã hoá đầu cuối; không có khoá giải mã, không lưu `sub` gốc
  (chỉ SHA-256 có tiền tố miền).
- **Kiểm quyền ở máy chủ** (PRODUCT_POLICY 7.1 N4): mọi lượt ghi kiểm JWS quyền lợi ES256 của tsudev.com - chỉ `ES256`,
  `typ` = `tsu-ent+jwt`, khoá theo `kid` từ JWKS lấy qua discovery, không khoá nhúng, không `crit`, kiểm `iss`, `aud`,
  `exp` (không nới), `iat`, `exp` ≤ `iat` + 7 ngày.
- **Chịu tải**: giới hạn thân yêu cầu, kích thước bản ghi/tệp, hạn mức theo tài khoản, tần suất ghi, trần toàn dịch vụ.
- **Không secret trong repo**: secret (`RP_PRIVATE_JWK`, `SUB_ENC_KEY`) chỉ đặt bằng `wrangler secret put`; test dùng giá trị giả. Log chỉ mã lỗi cố định, không
  JWS, không dữ liệu người dùng.
- **JWS tươi ≤ 24 giờ**, DPoP (RFC 9449) khi JWS gắn khoá thiết bị; chống phát lại `jti` (ADR-0002).
- **Không xoá nhầm**: xoá 90 ngày sau khi hết Pro chỉ khi tsudev.com xác nhận qua kênh trạng thái; lỗi ⇒ hoãn.
  `sub` lưu dạng AES-256-GCM (secret `SUB_ENC_KEY`), không dạng rõ.
