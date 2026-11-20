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
- **Không secret trong repo**: Worker không ký gì; cấu hình chỉ có giá trị công khai. Log chỉ mã lỗi cố định, không
  JWS, không dữ liệu người dùng.
- Rủi ro đã biết và chấp nhận: ADR-0001 mục 4-5 (JWS là bearer token ≤ 7 ngày; `pro_until` cũ khi xoá tự động).
