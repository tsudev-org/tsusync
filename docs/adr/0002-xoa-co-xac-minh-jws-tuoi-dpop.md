# ADR-0002: Xoá 90 ngày có xác minh với tsudev.com; JWS tươi ≤ 24 giờ và DPoP theo lộ trình

- **Trạng thái**: ĐÃ CHẤP NHẬN (thay mục 3.1 về thời hạn JWS và mục 3.7, 5 về xoá tự động của ADR-0001)
- **Ngày**: 20/11/2026
- **Người quyết định**: phiên điều phối tsudev, được chủ dự án uỷ quyền chọn phương án (20/11/2026)
- **Liên quan**: ADR-0001; `.standards/docs/PRODUCT_POLICY.md` mục 7.2, 7.4 (từ bộ quy ước v4.0.0: Pro theo kỳ 1 năm,
  kênh trạng thái quyền lợi); RFC 9449 (DPoP), RFC 7523 (private_key_jwt), RFC 7638 (JWK thumbprint)

## 1. Bối cảnh

ADR-0001 để lại hai rủi ro:

1. **Xoá nhầm**: máy chủ chỉ biết `pro_until` qua JWS app gửi lên. Người gia hạn trên web mà không mở app suốt 90 ngày
   sau mốc hết hạn cũ có thể bị xoá bản sao đám mây. Hỏi lại kênh RP hiện có (`GET /api/rp/entitlements/{sub}`) không đủ:
   kênh đó trả `404 unknown_subject` khi grant OIDC của tài khoản với client đã quá 30 ngày - đúng ca người không mở app.
2. **JWS là bearer token 7 ngày**: lộ JWS ⇒ kẻ khác đọc được bản mã trong tối đa 7 ngày.

Ràng buộc: 0 đồng; không thêm dịch vụ; máy chủ không giữ `sub` dạng rõ; app vẫn chạy cục bộ khi mạng/tsudev.com lỗi.

## 2. Các phương án đã cân nhắc

| Vấn đề | Phương án | Kết luận |
| --- | --- | --- |
| Xoá nhầm | A. Tắt xoá tự động vĩnh viễn | Loại: trái PRODUCT_POLICY 7.2, dữ liệu chết chiếm hạn mức miễn phí |
| | B. Kéo dài ân hạn (1 năm) | Loại: chỉ đẩy rủi ro ra xa, vẫn xoá nhầm được |
| | C. **Hỏi tsudev.com ngay trước khi xoá** qua kênh trạng thái mới (không phụ thuộc grant 30 ngày); lỗi/không rõ ⇒ hoãn | **Chọn** - tsudev.com là nguồn sự thật duy nhất về Pro |
| | D. tsudev.com đẩy webhook mỗi lần gia hạn | Bổ trợ được về sau; một mình D không đủ (mất webhook ⇒ xoá nhầm) |
| Bearer token | A. Giữ 7 ngày | Loại |
| | B. **JWS tươi ≤ 24 giờ** (theo `iat`) | **Chọn ngay** - app có mạng thì lấy JWS mới rẻ (1 yêu cầu/ngày) |
| | C. **DPoP (RFC 9449)**: JWS gắn khoá thiết bị (`cnf.jkt`) + bằng chứng ký mỗi yêu cầu | **Chọn theo lộ trình** - cần tsudev.com cấp `cnf.jkt` và thư viện máy khách ký DPoP |
| | D. Phiên riêng của TsuDEV Sync (đổi JWS lấy token) | Loại: kẻ có JWS cũng đổi được; thêm trạng thái |

## 3. Quyết định

### 3.1. Xoá có xác minh (`PURGE_MODE = "verified"`, mặc định)

- D1 lưu thêm `sub_enc` = nonce ‖ AES-256-GCM(`sub`), AAD = không gian tên, khoá ở secret `SUB_ENC_KEY` (32 byte).
  Dump D1 không lộ `sub`; khoá mất ⇒ không tự xoá được (an toàn theo hướng giữ dữ liệu).
- Lượt dọn chọn tài khoản có `pro_until` + 90 ngày < bây giờ, gom theo không gian tên, gọi
  `POST https://tsudev.com/api/rp/entitlements/status` (client `tsusync`, client assertion ES256 `private_key_jwt`,
  `aud` = URL kênh, ≤ 120 giây, `jti` một lần), thân `{"client_id": "<ns>", "subs": [...]}` (≤ 100):
  - `ok` và `pro_until` + 90 ngày > bây giờ (đã gia hạn) ⇒ cập nhật `pro_until`, **giữ dữ liệu**;
  - `ok` đã quá 90 ngày, hoặc `deleted` (tài khoản đã xoá ở tsudev.com) ⇒ đánh dấu `purge_requested`, xoá theo lô;
  - `unknown_subject`, lỗi mạng/HTTP, khung sai, không giải được `sub_enc` ⇒ **hoãn**, hỏi lại sau 24 giờ.
- Thiếu `RP_PRIVATE_JWK`/`SUB_ENC_KEY` hoặc `PURGE_MODE = "off"` ⇒ không bao giờ tự xoá. Yêu cầu xoá của chính người
  dùng (`DELETE /v1/account`) luôn chạy.
- Hợp đồng kênh trạng thái được đưa vào PRODUCT_POLICY 7.4 (bộ quy ước v4.0.0); tsudev.com triển khai theo phiếu
  `tsudev/logs/handover/20261120-PRO2_*` (cho phép client `tsusync` hỏi thay các `client_id` trong NAMESPACES).

### 3.2. JWS tươi và DPoP

- Nhận JWS có `iat` ≥ bây giờ - 24 giờ; cũ hơn ⇒ `401 {"error":"invalid_token","reason":"stale"}` - máy khách lấy JWS
  mới từ `/api/me/entitlements` rồi thử lại đúng một lần.
- JWS có `cnf.jkt` ⇒ bắt buộc `Authorization: DPoP <jws>` + header `DPoP`: `typ` = `dpop+jwt`, ES256, khoá P-256 trong
  header có thumbprint = `jkt`, `htm`/`htu` khớp (bỏ query), `iat` ±60 giây, `jti` chưa dùng (chống phát lại theo
  isolate), `ath` = base64url(SHA-256(JWS)). Sai ⇒ 401 `reason: "invalid_dpop_proof"`.
- Lộ trình: (1) v0.2.0 nhận cả JWS thường lẫn JWS gắn khoá; (2) tsudev.com cấp `cnf.jkt` khi app gửi DPoP tới
  `/api/me/entitlements`; thư viện `@tsudev/sync`/Dart `tsusync` (PRO-D2) và `tsudev_ui` ký DPoP; (3) khi mọi máy khách
  đã gửi DPoP ⇒ đặt `DPOP_REQUIRED = "on"` (JWS không gắn khoá ⇒ 401 `dpop_required`).

### 3.3. Pro theo kỳ 1 năm (PRODUCT_POLICY 7.2, v4.0.0)

Máy chủ không đổi logic: vẫn dựa trên `pro_until` của JWS / kênh trạng thái. Hết kỳ mà không gia hạn ⇒ `402` khi đẩy
(trạng thái miễn phí - "khách mời"), kéo/xuất thêm 90 ngày, sau đó xoá có xác minh như mục 3.1.

## 4. Hệ quả

**Tích cực:** không xoá nhầm người đã gia hạn ở bất kỳ kênh nào; cửa sổ dùng lại JWS bị lộ giảm từ 7 ngày xuống
24 giờ, về 0 khi bật DPoP; không thêm dịch vụ, vẫn 0 đồng (thêm ≤ 20 tài khoản × 1 yêu cầu/ngày tới tsudev.com).

**Tiêu cực:** thêm 2 secret khi deploy; phụ thuộc tsudev.com triển khai kênh trạng thái (chưa có ⇒ an toàn: không xoá).
App ngoại tuyến > 24 giờ phải lấy JWS mới trước khi đồng bộ (không ảnh hưởng dùng cục bộ).

**Việc phát sinh:** phiếu PRO2 cho tsudev (kênh trạng thái, DPoP ở `/api/me/entitlements`, email nhắc), tsudev_ui
(DPoP, nhắc gia hạn 7 ngày), PRO-D2 (thư viện ký DPoP, xử lý `stale`).

## 5. Đường lùi

`PURGE_MODE = "off"` tắt xoá tự động ngay (biến môi trường, không cần deploy mã). `DPOP_REQUIRED = "off"` quay về nhận
JWS thường. Cột `sub_enc`, `purge_checked_at` để trống không ảnh hưởng chức năng khác.
