# Kiến trúc - tsusync

Kiến trúc và hợp đồng: [`adr/0001-kien-truc-tsudev-sync.md`](adr/0001-kien-truc-tsudev-sync.md).

## Hạn mức đang dùng

| Dịch vụ | Gói | Hạn mức | Mức dùng gần nhất | Cập nhật |
| --- | --- | --- | --- | --- |
| Cloudflare Workers | Free | 100.000 yêu cầu/ngày, 10 ms CPU/yêu cầu | 0 (chưa deploy) | 20/11/2026 |
| Cloudflare D1 | Free | 500 MB/cơ sở dữ liệu; 5 triệu dòng đọc + 100.000 dòng ghi/ngày | 0 (chưa tạo) | 20/11/2026 |
| Cloudflare R2 | Free | 10 GB-tháng; 1 triệu Class A + 10 triệu Class B/tháng | 0 (chưa tạo) | 20/11/2026 |
