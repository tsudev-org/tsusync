# AGENTS.md - tsusync

> **ĐỌC FILE NÀY ĐẦU TIÊN trong mọi phiên làm việc mới.**

## Phần A - Quy ước chung của hệ sinh thái (KHÔNG SỬA Ở ĐÂY)

Toàn bộ quy ước chung nằm trong bản sao chỉ-đọc tại
[`.standards/AGENTS.md`](.standards/AGENTS.md). `MUST` đọc file đó trước.

Bản quy ước repo này đang dùng: xem [`.standards-version`](.standards-version).

| Cần gì | Đọc file nào |
| --- | --- |
| Điểm vào, nguyên tắc chung | `.standards/AGENTS.md` |
| Quy trình phiên, khóa file, bàn giao | `.standards/docs/AGENT_PROTOCOL.md` |
| Bảo mật bắt buộc | `.standards/docs/SECURITY_BASELINE.md` |
| Quy tắc `.gitignore` | `.standards/docs/GITIGNORE_POLICY.md` |
| Nhánh, commit, PR, phát hành | `.standards/docs/GIT_WORKFLOW.md` |
| Đăng nhập, đăng ký, xác minh tài khoản | `.standards/docs/AUTH_AND_ACCOUNT.md` |
| Giao diện và token | `.standards/docs/DESIGN_SYSTEM.md` |
| Bảng bản ghi, bộ chọn số bản ghi | `.standards/docs/DATA_TABLE.md` |
| Logo, favicon, icon ứng dụng | `.standards/docs/BRAND_ASSETS.md` |
| tsudev.com, ảnh đại diện, trang hồ sơ | `.standards/docs/ECOSYSTEM_IDENTITY.md` |
| Cấu trúc thư mục | `.standards/docs/PROJECT_STRUCTURE.md` |
| Chọn ngôn ngữ, framework | `.standards/docs/LANGUAGE_SELECTION.md` |
| Hạ tầng 0 đồng | `.standards/docs/FREE_TIER_STACK.md` |
| Trình soạn thảo nội dung | `.standards/docs/RICH_TEXT_EDITOR.md` |
| Tìm kiếm và lọc tiếng Việt | `.standards/docs/SEARCH_AND_FILTER.md` |
| Kiểm thử và chất lượng mã | `.standards/docs/TESTING_QUALITY.md` |
| Khả năng truy cập | `.standards/docs/ACCESSIBILITY.md` |

`MUST NOT` sửa bất kỳ file nào trong `.standards/`. Cần đổi quy ước thì mở đề
xuất tại repo `tsudev-standards` theo `.standards/docs/SYNC.md` mục 1.

## Phần B - Riêng của repo này

> Phần này KHÔNG thuộc bộ quy ước chung. Điền theo thực tế của repo.

### B.1. Repo này là gì

- **Loại**: dịch vụ **TsuDEV Sync** - máy chủ đồng bộ bản mã dùng chung cho sản phẩm không có máy chủ riêng
  (PRODUCT_POLICY 7.4). Thư viện máy khách TypeScript `@tsudev/sync` (`clients/ts`), Dart `tsusync` (`clients/dart`) và crate Rust `tsusync`
  (`clients/rust`, phần mã hoá), vector đối chiếu ở `conformance/` (ADR-0003). .NET ở PRO-D3.
- **Stack**: Cloudflare Workers + D1 + R2, TypeScript, Hono, jose (kiểm JWS ES256, DPoP), zod. Chi tiết: `docs/adr/`.
- **Mức phân loại dữ liệu cao nhất**: D3 nhưng CHỈ ở dạng bản mã (máy chủ không có khoá); siêu dữ liệu D1.
- **Người liên hệ khi có sự cố**: chủ dự án tsudev.

### B.2. Chạy trong 5 phút

```bash
cd worker
npx -y npm@11.21.2 ci --no-fund --no-audit
npm run check                      # typecheck + lint + test (Miniflare: D1/R2 giả lập, không cần token)
node scripts/audit.mjs             # cổng lỗ hổng phụ thuộc
npx wrangler deploy --dry-run --outdir /tmp/tsusync-build   # chỉ dựng, KHÔNG deploy
```

### B.3. Ranh giới sở hữu file

| Vùng | Chủ sở hữu |
| --- | --- |
| `worker/src/auth.ts` | phiên điều phối (hợp đồng PRODUCT_POLICY 7.4 - phải trùng `EntitlementVerifier` của tsudev_ui) |
| `worker/migrations/` | phiên điều phối - chỉ THÊM migration mới, không sửa migration đã gộp |
| `worker/src/*` còn lại, `docs/adr/` | phiên điều phối |
| `clients/`, `conformance/` | phiên điều phối - đổi khuôn byte ⇒ ADR mới + vector mới, KHÔNG sửa `vectors-v1.json` |

### B.4. Điểm lệch chuẩn đã biết

| Lệch ở đâu | Vì sao | Kế hoạch |
| --- | --- | --- |
| Chưa có `docs/ARCHITECTURE.md` đầy đủ | Kiến trúc nằm ở ADR-0001; `docs/ARCHITECTURE.md` chỉ giữ bảng hạn mức | Mở rộng khi deploy |
| TypeScript ghim 6.0.x (Dependabot bỏ qua ≥ 6.1) | `typescript-eslint` 8.73 chỉ hỗ trợ TypeScript < 6.1 | Gỡ dòng `ignore` trong `.github/dependabot.yml` khi `typescript-eslint` hỗ trợ |

### B.5. Việc riêng của repo cần biết trước khi sửa

- `clients/dart` không chạy được trên máy không có Dart SDK: CI (job `client-dart`) là nơi kiểm; định dạng theo
  `page_width: 120` của `analysis_options.yaml`.
- `clients/rust` dùng `dryoc` (libsodium viết lại bằng Rust, ghim `=2.0.1`) - KHÔNG phải libsodium C, nên bằng chứng đúng
  là vector + libsodium C độc lập (job `client-rust`). Nâng `dryoc` ⇒ chạy lại cả hai. Toolchain ghim ở
  `clients/rust/rust-toolchain.toml`; phụ thuộc được tối ưu cả ở test (Argon2id 64 MiB ở debug rất chậm).
- **KHÔNG deploy, KHÔNG tạo tài nguyên Cloudflare** khi chưa có sản phẩm dùng và chủ dự án chưa duyệt (ADR-0001 mục 4).
  `database_id` trong `wrangler.jsonc` là chỗ giữ chỗ.
- Mọi tính năng mới phải ước lượng lại hạn mức miễn phí (ADR-0001 mục 1.1). Cần vượt ⇒ dừng, hỏi chủ dự án.
- Đổi hợp đồng HTTP (đường dẫn, mã lỗi, khung JSON) ⇒ tăng phiên bản theo SemVer, ghi CHANGELOG, cập nhật thư viện máy
  khách cùng lúc.
- Xoá tự động chỉ chạy khi tsudev.com xác nhận qua kênh trạng thái (`PURGE_MODE = "verified"`, ADR-0002). Không bao
  giờ đổi sang xoá không xác minh. `wrangler.test.jsonc` dùng CÙNG `compatibility_date` với `wrangler.jsonc`.
- Secret khi deploy: `RP_PRIVATE_JWK`, `SUB_ENC_KEY` (ADR-0002). Test dùng giá trị giả trong `vitest.config.ts`.
