# TsuDEV Sync (tsusync)

> ⛔ **ĐÃ NGỪNG TỪ 25/11/2026 - repo chỉ còn để đọc (archived).** Chủ dự án quyết định dữ liệu người dùng của hệ TsuDEV
> **không** lên internet hay máy chủ đồng bộ nữa (tsudev-standards **v7.0.0**, `PRODUCT_POLICY` mục 7, quyền lợi Pro Q3
> bị bỏ). Dịch vụ này **chưa từng được triển khai** (không có dữ liệu người dùng thật). Đồng bộ giữa thiết bị nay làm
> trực tiếp qua mạng nội bộ bằng **[Tsu Link](https://github.com/tsudev-org/tsulink)** (`LOCAL_SYNC.md`); vector mật
> mã `conformance/vectors-v1.json` đã chuyển sang `tsulink` cho định dạng sao lưu `.tsubak`.
>
> ⛔ **Discontinued on 25/11/2026 (archived, read-only).** TsuDEV no longer sends user data to the internet or a sync
> server. This service was never deployed. Device-to-device sync now lives in [Tsu Link](https://github.com/tsudev-org/tsulink).

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16955/badge)](https://www.bestpractices.dev/projects/16955)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/tsudev-org/tsusync/badge)](https://scorecard.dev/viewer/?uri=github.com/tsudev-org/tsusync)

Dịch vụ đồng bộ và sao lưu đám mây **dùng chung** của hệ sinh thái tsudev cho các sản phẩm không có máy chủ riêng
(desktop, trò chơi, tsufiles, lotus-share...). Chỉ dành cho tài khoản **TsuDEV Pro**; máy chủ chỉ giữ **bản mã**.

Mọi app TsuDEV miễn phí, mã nguồn mở; TsuDEV Pro là gói tuỳ chọn để ủng hộ tác giả. Đồng bộ + sao lưu đám mây là
quyền lợi Q3 của Pro (PRODUCT_POLICY 3.7.1) vì chỉ phần này tốn dung lượng máy chủ; xuất/nhập/sao lưu ra tệp trong app
luôn miễn phí.

- Kiến trúc và hợp đồng HTTP: [`docs/adr/0001-kien-truc-tsudev-sync.md`](docs/adr/0001-kien-truc-tsudev-sync.md)
- Hạn mức đang dùng: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Máy chủ: [`worker/`](worker/) - Cloudflare Workers + D1 + R2

## API (v1)

| Phương thức | Đường dẫn | Cần | Ghi chú |
| --- | --- | --- | --- |
| GET | `/v1/health` | - | |
| GET | `/v1/account` | JWS | hạn mức, `rev`, `read_until` |
| DELETE | `/v1/account` | JWS | xoá dữ liệu đám mây của mình (không cần Pro) |
| GET | `/v1/records?since=&limit=` | Pro hoặc ≤ 90 ngày sau hết hạn | delta theo `rev` |
| POST | `/v1/records` | Pro | ≤ 100 mục, idempotent |
| GET | `/v1/files?since=&limit=` | Pro hoặc ≤ 90 ngày | |
| PUT | `/v1/files/{id}` | Pro | `Content-Length`, `X-Tsu-Digest` |
| GET / DELETE | `/v1/files/{id}` | Pro hoặc ≤ 90 ngày | |

Xác thực: `Authorization: Bearer <JWS quyền lợi>` lấy từ `GET https://tsudev.com/api/me/entitlements`, `iat` ≤ 24 giờ
(cũ hơn ⇒ `401 reason: "stale"`). JWS gắn khoá thiết bị (`cnf.jkt`) ⇒ `Authorization: DPoP <jws>` + header `DPoP`
(RFC 9449). Không có Pro ⇒ `402 {"error":"pro_required"}`. Xoá 90 ngày sau khi hết Pro chỉ khi tsudev.com xác nhận
không gia hạn (ADR-0002).

## Thư viện máy khách

| Ngôn ngữ | Thư mục | Dùng |
| --- | --- | --- |
| TypeScript `@tsudev/sync` | `clients/ts` | web/desktop: `await ready()`, `createKeys`/`unlockKeys`, `SyncClient`, `SyncSession` |
| Dart `tsusync` | `clients/dart` | app Flutter: git dependency ghim commit (`path: clients/dart`); DPoP nối `DpopSigner` của `tsudev_ui` |
| Rust `tsusync` | `clients/rust` | app Rust/Tauri: git dependency ghim commit; CHỈ phần mã hoá (`create_keys`/`unlock_keys`, `encrypt`/`decrypt`) - chưa có máy khách HTTP |
| .NET `Tsudev.Sync` | `clients/dotnet` | app .NET 8+ (WinUI/MAUI/Avalonia): ProjectReference ghim commit; CHỈ phần mã hoá (`TsuSyncCrypto`), libsodium C qua gói NuGet `libsodium` |

Định dạng bản mã và khoá: `docs/adr/0003-ma-hoa-may-khach-dinh-dang-ts01.md`. Mọi thư viện phải qua
`conformance/vectors-v1.json`; kiểm độc lập: `python3 -I conformance/verify_libsodium.py conformance/vectors-v1.json`.

## Phát triển

```bash
cd worker
npx -y npm@11.21.2 ci --no-fund --no-audit
npm run check
```

## Triển khai

**Chưa triển khai.** Chỉ deploy khi có sản phẩm dùng và chủ dự án duyệt (ADR-0001 mục 4): tạo D1 `tsusync`, R2
`tsusync-files`, điền `database_id` + `NAMESPACES` trong `worker/wrangler.jsonc`, đặt secret `RP_PRIVATE_JWK` + `SUB_ENC_KEY`
(ADR-0002), áp migration, route `sync.tsudev.com`.

## English summary

TsuDEV Sync (AGPL-3.0-only) is the shared **end-to-end encrypted** sync and backup service of the TsuDEV apps that have
no server of their own. It is available to **TsuDEV Pro** accounts only, and the server stores **ciphertext only**.
Every TsuDEV app is free and open source; TsuDEV Pro is an optional plan to support the author, and cloud sync is one
of its benefits because it is the part that costs server storage. Export/import/backup to a file stays free.

- **Server**: a Cloudflare Worker (`worker/`, D1 + R2) with a small HTTP API (records with a `rev` cursor, files,
  account quota and deletion). Every request carries the ES256 entitlement JWS from tsudev.com (fresh within 24 hours,
  DPoP-bound when the token has a device key); without Pro it answers `402 pro_required`.
- **Clients**: TypeScript `@tsudev/sync`, Dart `tsusync`, Rust `tsusync` and .NET `Tsudev.Sync` all implement the same
  `TS 01` ciphertext format (libsodium secretstream XChaCha20-Poly1305 in 64 KiB chunks, Argon2id keys, context-bound
  associated data) and pass the shared vectors in `conformance/vectors-v1.json`, cross-checked with libsodium C.

Build and test instructions are in [CONTRIBUTING.md](CONTRIBUTING.md); report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md); changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Giấy phép

AGPL-3.0-only - xem [`LICENSE`](LICENSE) và [`NOTICE`](NOTICE).
