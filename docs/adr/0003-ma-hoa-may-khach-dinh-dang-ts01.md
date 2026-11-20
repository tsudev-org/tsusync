# ADR-0003: Mã hoá máy khách - định dạng `TS 01`, khoá Argon2id + crypto_kdf, vector đối chiếu chéo

- **Trạng thái**: ĐÃ CHẤP NHẬN
- **Ngày**: 20/11/2026
- **Người quyết định**: phiên điều phối (PRO-D2)
- **Liên quan**: PRODUCT_POLICY 7.4 (v4.0.0), qulythuchi ADR-0007, ADR-0001 mục 3.3-3.4, `clients/ts`, `clients/dart`,
  `conformance/`

## 1. Bối cảnh

PRODUCT_POLICY 7.4 bắt buộc: libsodium `crypto_secretstream_xchacha20poly1305`, khoá suy bằng Argon2id ≥ 64 MiB / 3
lượt từ mật khẩu đồng bộ đã chuẩn hoá NFKC, máy chủ không giữ khoá, có vector đối chiếu chéo 4 ngôn ngữ. Hợp đồng
chưa chốt khuôn byte, nên mỗi thư viện tự chọn sẽ cho ra bản mã không đọc chéo được. ADR này chốt khuôn đó.

## 2. Quyết định

### 2.1. Khoá

1. Mật khẩu: NFKC, rồi đếm theo **code point** (không theo đơn vị UTF-16): < 10 ⇒ từ chối (`weak_password`).
2. Gốc = `crypto_pwhash` Argon2id13, 32 B, muối ngẫu nhiên 16 B. Mặc định **3 lượt / 64 MiB** (qulythuchi ADR-0007).
   Khi mở khoá: dưới **2 lượt / 19 MiB** (sàn OWASP) hoặc trên **16 lượt / 1 GiB** ⇒ từ chối (`invalid_params`):
   máy chủ hay người sửa dữ liệu không ép được tham số yếu, cũng không làm cạn bộ nhớ thiết bị.
3. Khoá dữ liệu = `crypto_kdf_derive_from_key(32, 1, "TSUSYNC1", gốc)`; mã kiểm = `crypto_kdf_derive_from_key(16, 2,
   "TSUSYNC1", gốc)`. Mã kiểm cho biết mật khẩu sai ngay (`WrongPassword`) mà không phải giải mã thử; không suy ngược
   được khoá dữ liệu từ nó.
4. Tham số lưu dạng JSON (không bí mật): `{"v":1,"alg":"argon2id13","salt":"<b64u>","ops":3,"mem":67108864,
   "check":"<b64u>"}`. Nơi lưu (bản ghi riêng trên TsuDEV Sync hay máy chủ sản phẩm) do sản phẩm chọn.

### 2.2. Bản mã `TS 01`

```
'T' 'S' 0x01 <loại: 0x01 bản ghi | 0x02 tệp> ‖ header secretstream (24 B) ‖ khối_0 ‖ ... ‖ khối_{n-1}
```

- Bản rõ được `sodium_pad` theo khối **256 B** (bản ghi) / **4096 B** (tệp) để giấu cỡ, rồi cắt khối **64 KiB**.
  Mỗi khối mã = khối rõ + 17 B. Khối cuối mang `TAG_FINAL`, mọi khối trước `TAG_MESSAGE`. `sodium_pad` luôn thêm ≥ 1
  byte nên luôn có ít nhất một khối.
- AAD của **mọi** khối = 4 byte đầu ‖ UTF-8(`tsusync|v1|<namespace>|<rec|file>|<id>`), `namespace` = `client_id` của
  sản phẩm, `id` = định danh bản ghi/tệp trên máy chủ (`[A-Za-z0-9._~:-]{1,128}`). Máy chủ tráo bản mã sang id, sản
  phẩm hay loại khác ⇒ không mở được.
- Bên giải mã `MUST`: kiểm tiền tố; tính số khối từ độ dài (khối trước đầy 65 553 B, khối cuối ≥ 17 B); `TAG_FINAL`
  đúng ở khối cuối và chỉ ở đó (chống cắt cụt, chống nối thêm); `sodium_unpad` thành công. Mọi lỗi trả MỘT loại lỗi
  chung, không nói lý do.
- Bản ghi sau mã hoá phải ≤ 64 KiB (giới hạn `payload` của ADR-0001 mục 3.3); tệp ≤ 64 MiB mỗi lần PUT, lớn hơn thì
  sản phẩm tự chia.

### 2.3. Vector đối chiếu

- `conformance/vectors-v1.json` (sinh bởi `clients/ts/scripts/gen-vectors.ts`): 7 ca mở được (rỗng, UTF-8, biên đệm
  255/256, đúng 1 khối đầy, 2 và 3 khối), 16 ca `must_fail` mô tả bằng đột biến (lật bit header/MAC/khối giữa, cắt
  byte, bỏ khối cuối, nối sau `TAG_FINAL`, đổi chỗ khối, sai id/namespace/loại/phiên bản/khoá, quá ngắn), 5 ca suy
  khoá (NFC = NFD, toàn khổ = ASCII sau NFKC, 10 emoji = 10 code point), 6 ca từ chối KDF, 2 ca mở khoá bằng JSON.
- Header secretstream ngẫu nhiên nên sinh lại cho ra tệp khác: tệp đã commit là hợp đồng, chỉ sinh lại khi đổi định
  dạng (định dạng mới + ADR mới; dữ liệu cũ vẫn phải đọc được).
- Ba cài đặt độc lập phải qua: TypeScript (`libsodium-wrappers-sumo`), Dart (`sodium`), Python ctypes trên libsodium C
  của hệ điều hành (`conformance/verify_libsodium.py`). CI còn kiểm chiều ngược: bản mã do TypeScript và Dart VỪA tạo
  phải mở được bằng bộ kiểm Python. Rust crate và .NET (PRO-D3) phải qua cùng tệp.

### 2.4. Máy khách HTTP

- `402 pro_required` ⇒ lỗi riêng (`ProRequiredError`/`ProRequiredException`) mang `reason`; không thử lại.
- `401 reason=stale` ⇒ gọi `getJws(true)` rồi thử lại đúng một lần (PRODUCT_POLICY 7.4, ADR-0002 mục 3.2).
- DPoP: thư viện nhận hàm ký bằng chứng `(method, url không query, jws)` thay vì tự giữ khoá - Dart nối với
  `DpopSigner.proof` của `tsudev_ui`; app TypeScript truyền hàm ký của mình (ví dụ WebCrypto P-256). Có hàm ký ⇒ `Authorization: DPoP`.
- `baseUrl` bắt buộc: dịch vụ chưa có tên miền chính thức (chưa deploy, ADR-0001 mục 4).

## 3. Phương án đã loại

- `crypto_secretbox` / `crypto_aead_xchacha20poly1305_ietf` một khối như phong bì qulythuchi: không phát trực tuyến
  được tệp lớn, trái PRODUCT_POLICY 7.4.
- Dùng thẳng gốc Argon2id làm khoá dữ liệu: không có mã kiểm mật khẩu, và không tách được khoá con khi cần thêm (đổi
  khoá, chia sẻ) mà không đổi định dạng.
- Vector sinh tất định bằng header cố định: libsodium không cho đặt header `init_push`; tự cài `init_push` là tự viết
  mật mã. Thay bằng vector giải mã + kiểm chiều ngược trên CI.

## 4. Hệ quả

- Thêm ngôn ngữ mới chỉ cần qua `conformance/vectors-v1.json` + `verify_libsodium.py` cho bản mã nó tạo ra.
- Ngữ nghĩa đột biến `must_fail` (`flip` âm tính từ cuối, `drop_last_chunk`, `swap_chunks`, `set_byte`...) phải trùng
  ở mọi bộ test; tham chiếu là `conformance/verify_libsodium.py`.
- Đổi bất kỳ điểm nào ở mục 2.1-2.2 ⇒ byte phiên bản mới + ADR mới + vector mới.
