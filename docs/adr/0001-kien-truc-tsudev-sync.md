# ADR-0001: TsuDEV Sync chạy trên Workers + D1 + R2, mỗi sản phẩm một không gian tên, chỉ cho tài khoản Pro

- **Trạng thái**: ĐÃ CHẤP NHẬN - mục 3.1 (thời hạn JWS), 3.7 và 5 (xoá tự động) được ADR-0002 thay thế
- **Ngày**: 20/11/2026
- **Người quyết định**: phiên điều phối tsudev (phase PRO-D1), theo quyết định của chủ dự án 19/11/2026 (phiếu `20261119-PRO1`)
- **Liên quan**: `.standards/docs/PRODUCT_POLICY.md` mục 7.1, 7.2, 7.4, 7.5; `.standards/docs/FREE_TIER_STACK.md` mục 3.1;
  `tsudev-org/tsudev-ui-flutter` ADR-0001 (kiểm JWS ở app); qulythuchi ADR-0016 (máy chủ đồng bộ riêng, kênh RP)

## 1. Bối cảnh

Sản phẩm không có máy chủ riêng (desktop, trò chơi, tsufiles, lotus-share...) cần đồng bộ/sao lưu đám mây cho người
dùng TsuDEV Pro (PRODUCT_POLICY 7.1 N3). Bộ quy ước đã chốt tên và hình dạng dịch vụ (7.4): repo `tsudev-org/tsusync`,
Workers + D1 + R2, mỗi sản phẩm một không gian tên, không có Pro ⇒ `402 {"error":"pro_required"}`.

- Ràng buộc kỹ thuật: Worker gói Free có 10 ms CPU/yêu cầu, 50 truy vấn D1/lượt gọi, 100 tham số/truy vấn; máy chủ
  không được tin cờ từ app (N4); đồng bộ delta theo `rev`, idempotent, chịu lỗi (N5).
- Ràng buộc 0 đồng (N7, FREE_TIER_STACK 3.1): người dùng miễn phí không tốn dung lượng máy chủ; vượt hạn mức miễn phí
  ⇒ dừng, hỏi chủ dự án.
- Phân loại dữ liệu: nội dung đồng bộ là D2+ của người dùng ⇒ máy chủ CHỈ giữ bản mã (mã hoá đầu cuối ở máy khách,
  libsodium secretstream + Argon2id, thư viện ở PRO-D2). Máy chủ thấy: `sub` (đã băm), `aud`, `pro_until`, định danh
  mờ của bản ghi/tệp, kích thước, thời điểm.

### 1.1. Hạn mức miễn phí Cloudflare - đo 20/11/2026 (Bước 0)

Nguồn: trang chính thức developers.cloudflare.com, đọc 20/11/2026 - `workers/platform/limits` (cập nhật 19/11/2026),
`workers/platform/pricing` (18/11/2026), `d1/platform/limits`, `r2/pricing`, `r2/platform/limits` (30/10/2026).

| Dịch vụ | Hạn mức gói Free | Ảnh hưởng tới thiết kế |
| --- | --- | --- |
| Workers - yêu cầu | 100.000/ngày (đặt lại 00:00 UTC); quá ⇒ lỗi 1027, không tính tiền | Không poll; app đồng bộ khi mở/sửa/quay lại, nền ≥ 10 phút |
| Workers - CPU | 10 ms/yêu cầu; quá ⇒ lỗi 1102 | Đệm kết quả kiểm JWS theo chuỗi JWS; không làm mật mã nặng ở máy chủ |
| Workers - bộ nhớ | 128 MB/isolate | Tệp đi thẳng luồng vào R2, không đệm toàn bộ; tệp ≤ 64 MiB |
| Workers - thân yêu cầu | 100 MB (theo gói tên miền) | Tệp ≤ 64 MiB/lần; lô bản ghi ≤ 3 MiB |
| Workers - khác | 50 subrequest/yêu cầu, 5 Cron/tài khoản (đã dùng hết), 100 Worker/tài khoản | Không dùng Cron: dọn dữ liệu chạy kèm ~1% yêu cầu |
| D1 - dung lượng | 500 MB/cơ sở dữ liệu, 5 GB/tài khoản, 10 cơ sở dữ liệu | Trần toàn dịch vụ 400 MiB (80%) cho bản ghi |
| D1 - đọc/ghi | 5 triệu dòng đọc, 100.000 dòng ghi mỗi ngày | Ghi theo lô; chỉ cập nhật `seen_at` 1 lần/ngày; dọn theo lô 500 dòng |
| D1 - truy vấn | 50/lượt gọi (1 `batch` = 1), 100 tham số/truy vấn, dòng ≤ 2 MB, câu lệnh ≤ 100 KB | Một lần đẩy = 1 batch ≤ 102 câu lệnh, mỗi câu ≤ 10 tham số; bản ghi ≤ 64 KiB |
| R2 - lưu trữ | 10 GB-tháng (Standard) | Trần toàn dịch vụ 8 GiB (80%) cho tệp |
| R2 - thao tác | 1 triệu Class A + 10 triệu Class B mỗi tháng; truyền ra 0 đồng | Tải lại tệp trùng digest ⇒ `unchanged`, không PUT lại |
| R2 - giới hạn | 5 GiB/PUT, 1 lần ghi/giây cùng khoá | Mỗi tệp một khoá riêng `<ns>/<sub_key>/<id>` |

Chưa xác nhận được "rate limiting binding" có ở gói Free (trang không nhắc) ⇒ không dùng; giới hạn tần suất làm bằng D1.

**Kết luận Bước 0: v0.1.0 KHÔNG cần vượt hạn mức miễn phí** (chưa deploy, chưa có tài nguyên thật, chưa có người dùng).
Sức chứa ở mức miễn phí, nếu mọi tài khoản Pro dùng TRỌN hạn mức: ~4 tài khoản (400 MiB D1 / 100 MiB) và ~8 tài khoản
(8 GiB R2 / 1 GiB). Dùng thực tế thường nhỏ hơn nhiều (vài MiB bản ghi/tài khoản), nhưng khi tổng chạm trần, máy chủ trả
`507 capacity_reached` + ghi cảnh báo, và đó là điểm **phải dừng, hỏi chủ dự án** (thêm cơ sở dữ liệu D1 thứ hai trong
giới hạn 10 × 500 MB, hoặc chuyển gói trả phí bằng doanh thu Pro) - Worker không bao giờ tự vượt.

## 2. Các phương án đã cân nhắc

| Phương án | Ưu | Nhược | Chi phí |
| --- | --- | --- | --- |
| A. Một Worker dùng chung, D1 (siêu dữ liệu + bản ghi nhỏ) + R2 (tệp), không gian tên = `aud` | Đúng PRODUCT_POLICY 7.4; một chỗ kiểm Pro; delta theo `rev` rẻ trên D1 | D1 500 MB/cơ sở dữ liệu giới hạn sức chứa bản ghi | 0 đồng tới trần mục 1.1 |
| B. Mọi thứ (cả bản ghi) trên R2, D1 chỉ chỉ mục | Sức chứa 10 GB | Mỗi bản ghi = 1 thao tác Class A/B; kéo delta cần nhiều GET ⇒ hết 1 triệu Class A/tháng nhanh | 0 đồng nhưng sớm chạm hạn mức thao tác |
| C. Durable Objects (SQLite) mỗi tài khoản một đối tượng | Tuần tự hoá tự nhiên | Trạng thái phân tán, khó dọn/thống kê; thêm sản phẩm Cloudflare | 0 đồng (5 GB) nhưng phức tạp hơn |
| D. Mỗi sản phẩm tự dựng máy chủ | Tách biệt | Trái PRODUCT_POLICY 7.4; nhân bản mã kiểm Pro | 0 đồng nhưng tốn công |

## 3. Quyết định

Chọn **A**. Chi tiết hợp đồng (máy khách ở PRO-D2 `MUST` theo đúng):

### 3.1. Xác thực và kiểm Pro (N4)

- App lấy JWS quyền lợi qua `GET https://tsudev.com/api/me/entitlements` (scope `tsudev.entitlements`) rồi gửi
  `Authorization: Bearer <jws>` tới TsuDEV Sync. Không có phiên/cookie riêng; Worker không giữ secret nào.
- Kiểm như `EntitlementVerifier` của tsudev_ui: chỉ `ES256`, `typ` = `tsu-ent+jwt`, có `kid`, không khoá nhúng/`crit`;
  JWKS lấy qua discovery của `OIDC_ISSUER` (`issuer` khớp, `jwks_uri` https cùng máy chủ), chỉ nhận khoá EC P-256; kiểm
  `iss`, `aud` ∈ `NAMESPACES`, `exp` (không nới), `iat` ≤ bây giờ + 2 phút, `exp` ≤ `iat` + 7 ngày, `pro_until` số ≥ 0.
  Kid lạ ⇒ tải lại JWKS tối đa 1 lần/60 giây. tsudev.com không trả lời ⇒ `503 entitlements_unavailable` + `Retry-After`.
- **Ghi** (đẩy bản ghi, tải tệp lên) cần `pro_until` > bây giờ; **đọc** (kéo, tải xuống, xoá tệp) được thêm 90 ngày sau
  `pro_until`; chưa từng có Pro ⇒ `402 {"error":"pro_required","reason":"no_pro"}`, quá 90 ngày ⇒ `reason:"grace_expired"`.
  App gặp 402 ⇒ hiện màn Pro, không thử lại.
- `X-Tsu-Installation` nếu gửi phải đúng 22 ký tự base64url; không lưu (đếm thiết bị là việc của tsudev.com).
- Máy chủ lưu `pro_until` của JWS có `iat` mới nhất cho từng tài khoản (dùng cho mốc xoá); JWS cũ hơn không ghi đè.

### 3.2. Không gian tên

- Không gian tên = `aud` của JWS = `client_id` của sản phẩm tại tsudev.com, phải có trong biến `NAMESPACES`. Cùng `sub`
  ở hai sản phẩm là hai tài khoản đồng bộ tách biệt (hạn mức riêng, dữ liệu riêng).
- Định danh tài khoản trong D1/R2 là `sub_key` = hex(SHA-256("tsusync|" + sub)) - không lưu `sub` gốc.
- Hạn mức riêng của sản phẩm (ADR của sản phẩm, chủ dự án duyệt) đặt ở biến `QUOTAS`.

### 3.3. Bản ghi và con trỏ `rev`

- `POST /v1/records` `{"items":[{"id","base_rev"?,"deleted"?,"payload"?}]}`: ≤ 100 mục, ≤ 2 MiB bản mã/lô, mỗi
  `payload` (base64url) ≤ 64 KiB. `id` là định danh mờ 1-128 ký tự `[A-Za-z0-9._~:-]` - máy khách `MUST NOT` đặt bản rõ
  (tên tệp, tiêu đề) vào `id`.
- Mỗi lần ghi nhận một `rev` mới, tăng dần trong (không gian tên, tài khoản), dùng chung cho bản ghi và tệp.
- Kết quả từng mục: `applied` (kèm `rev` mới), `unchanged` (cùng digest + trạng thái xoá - **idempotent**: gửi lại
  y hệt sau khi mất phản hồi không tạo bản sao, không tăng `rev`, không tính hạn mức lần hai), `conflict` (có `base_rev`
  mà lệch `rev` hiện tại; `base_rev` = 0 nghĩa là "chưa tồn tại"), `rejected` (`duplicate` | `invalid_payload`).
  Không có `base_rev` ⇒ ghi sau thắng. Hợp nhất nội dung là việc của máy khách (máy chủ không đọc được bản mã).
- Xoá = bia mộ (`deleted: true`, không payload), vẫn được kéo về để thiết bị khác xoá theo.
- `GET /v1/records?since=<rev>&limit=<≤500>` trả `{items, next, more}` theo thứ tự `rev`, tối đa ~4 MiB/trang.
- Ghi đồng thời: một batch D1 (giao dịch) có thẻ `lock` ngẫu nhiên - chỉ ghi nếu không ai ghi chen sau lúc đọc; ngược
  lại đọc lại và thử tối đa 4 lần rồi `503 busy` + `Retry-After`.

### 3.4. Tệp

- `PUT /v1/files/{id}` thân = bản mã, `Content-Length` bắt buộc (≤ 64 MiB, lớn hơn ⇒ máy khách chia khối),
  `X-Tsu-Digest` = base64url(SHA-256 bản mã) - R2 kiểm lại khi ghi (lệch ⇒ `400 digest_mismatch`). Cùng digest + cỡ
  ⇒ `unchanged`. `GET /v1/files?since=` liệt kê thay đổi theo `rev`; `GET`/`DELETE /v1/files/{id}`.
- Khoá R2: `<ns>/<sub_key>/<id>`.

### 3.5. Hạn mức (PRODUCT_POLICY 7.5, FREE_TIER_STACK 3.1)

- Mặc định mỗi tài khoản mỗi sản phẩm: **100 MiB** dữ liệu (bản ghi: payload + id + 64 byte/bản ghi, kể cả bia mộ)
  + **1 GiB** tệp. Vượt ⇒ `413 {"error":"quota_exceeded","kind":"data"|"files","limit":n}` cho CẢ lô - không cắt âm thầm.
- Giới hạn tần suất ghi: 120 lượt/phút/tài khoản (D1, cửa sổ cố định) ⇒ `429` + `Retry-After`.

### 3.6. Trần toàn dịch vụ (N7)

- Bảng `totals` cộng dồn byte đã dùng. Trần mặc định = 80% hạn mức miễn phí: `GLOBAL_DATA_BUDGET_MIB` = 400,
  `GLOBAL_FILE_BUDGET_MIB` = 8192. Chạm trần ⇒ `507 capacity_reached` (app coi như "Chưa đồng bộ", vẫn chạy cục bộ) và
  log cảnh báo `capacity_reached` để chủ dự án quyết định (mục 1.1).

### 3.7. Pro hết hạn và xoá dữ liệu (PRODUCT_POLICY 7.2)

- Hết Pro: chặn ghi ngay, cho kéo + tải xuống 90 ngày; app báo ở mốc 30 và 7 ngày dựa trên `read_until` của
  `GET /v1/account`. Quá 90 ngày ⇒ xoá dữ liệu trên máy chủ (dữ liệu trên thiết bị không bao giờ bị xoá).
- `DELETE /v1/account`: người dùng tự xoá dữ liệu đám mây của mình ở sản phẩm này, không cần Pro; trả `202`, chặn ghi
  (`409 purge_in_progress`) cho tới khi xoá xong.
- Không Cron (tài khoản đã hết 5 Cron gói Free): dọn chạy kèm ~1% yêu cầu và ngay sau `DELETE /v1/account`, mỗi lượt
  tối đa 2 tài khoản × 500 dòng/bảng × 500 đối tượng R2.

## 4. Hệ quả

**Tích cực:**
- Một chỗ kiểm Pro dùng chung cho mọi sản phẩm không có máy chủ; máy chủ không giữ secret, không giữ khoá giải mã.
- Đồng bộ delta rẻ (1 batch D1/lần đẩy, đọc chỉ mục theo `rev`), idempotent, chịu lỗi.

**Tiêu cực và chi phí phải trả:**
- JWS quyền lợi là bearer token (≤ 7 ngày): lộ JWS ⇒ kẻ khác đọc được BẢN MÃ của người đó trong thời hạn JWS. Giảm nhẹ:
  E2EE, TLS, JWS ngắn hạn, app không ghi log JWS. Có thể nâng lên ràng buộc khoá thiết bị (DPoP) ở ADR sau.
- Sức chứa miễn phí nhỏ (mục 1.1) - đủ cho giai đoạn đầu, phải theo dõi `totals`.
- Phát lại JWS cũ còn hạn (≤ 7 ngày) vẫn cho ghi nếu lúc ký còn Pro (ví dụ ngay sau hoàn tiền) - chấp nhận theo thời hạn JWS.

**Việc phát sinh cần làm:**
- [ ] PRO-D2: thư viện `@tsudev/sync` (TypeScript) + Dart `tsusync` + vector đối chiếu chéo (libsodium secretstream,
  Argon2id ≥ 64 MiB / 3 lượt, NFKC - thông số qulythuchi ADR-0007).
- [ ] Trước khi deploy (khi có sản phẩm dùng, chủ dự án duyệt): tạo D1 `tsusync` + R2 `tsusync-files`, điền
  `database_id`, `NAMESPACES`; route `sync.tsudev.com`; bật cảnh báo 80% hạn mức (FREE_TIER_STACK 3).
- [ ] Trước khi bật `PURGE_ENABLED = "on"`: xem mục 5.

## 5. Đường lùi và rủi ro đã biết

- **`pro_until` cũ khi xoá tự động**: máy chủ chỉ biết `pro_until` qua JWS app gửi lên. Người gia hạn Pro trên web mà
  không mở app suốt 90 ngày sau mốc hết hạn cũ có thể bị xoá nhầm bản sao đám mây (dữ liệu trên thiết bị vẫn còn). Vì vậy
  xoá tự động mặc định TẮT (`PURGE_ENABLED = "off"`); bật khi chủ dự án duyệt, tốt nhất sau khi TsuDEV Sync đăng ký làm RP
  để hỏi lại `GET /api/rp/entitlements/{sub}` ngay trước khi xoá (cần lưu `sub` mã hoá - ADR riêng).
- Hết sức chứa miễn phí ⇒ `507`, app vẫn chạy cục bộ; đường lùi là thêm cơ sở dữ liệu D1 (chia theo không gian tên)
  hoặc trả phí khi chủ dự án duyệt.
- Bỏ dịch vụ: người dùng xuất bản mã qua kéo/tải xuống trong 90 ngày; dữ liệu chính luôn ở thiết bị (N1).
