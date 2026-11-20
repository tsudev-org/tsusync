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

## English summary

- **Reporting**: do **not** open a public issue. Use GitHub
  [private vulnerability reporting](https://github.com/tsudev-org/tsusync/security/advisories/new) with the affected
  component, version (tag), steps to reproduce and impact. We reply within 7 days and ship a fix for serious issues
  within 30 days; fixed vulnerabilities are named in [CHANGELOG.md](CHANGELOG.md).
- **Zero knowledge**: the server only receives ciphertext encrypted end to end by the clients (libsodium secretstream
  XChaCha20-Poly1305, keys from Argon2id); it has no decryption key and stores only a domain-separated SHA-256 of the
  user id (`sub`), encrypted with AES-256-GCM where it must be kept.
- **Server-side authorization**: every request verifies the ES256 entitlement JWS of tsudev.com - only `ES256`,
  `typ` = `tsu-ent+jwt`, key by `kid` from the discovered JWKS, no embedded keys, no `crit`, `iss`/`aud`/`exp`/`iat`
  checked, lifetime ≤ 7 days, `iat` ≤ 24 hours, DPoP (RFC 9449) with `jti` replay protection when the token is bound
  to a device key.
- **Abuse limits**: request body, record and file size limits, per-account quotas, write rate limits and a global cap.
- **No secrets in the repository**: secrets are set with `wrangler secret put` only; tests use fake values; gitleaks
  and GitHub push protection guard every push. Logs contain fixed error codes only, never tokens or user data.
- **Untrusted input**: the decryptors accept only the original plaintext or a fixed rejection error; a seeded fuzz test
  (`clients/ts/test/fuzz.test.ts`) checks this for mutated ciphertext, KDF parameters and base64url strings.
