# TsuDEV Sync (tsusync)

Dịch vụ đồng bộ và sao lưu đám mây **dùng chung** của hệ sinh thái tsudev cho các sản phẩm không có máy chủ riêng
(desktop, trò chơi, tsufiles, lotus-share...). Chỉ dành cho tài khoản **TsuDEV Pro**; máy chủ chỉ giữ **bản mã**.

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

## Giấy phép

AGPL-3.0-only - xem [`LICENSE`](LICENSE) và [`NOTICE`](NOTICE).
