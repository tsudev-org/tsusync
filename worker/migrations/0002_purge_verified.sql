-- ADR-0002: xoá 90 ngày sau khi hết Pro CHỈ khi tsudev.com xác nhận không gia hạn.
-- `sub_enc` = nonce || AES-256-GCM(sub), AAD = ns, khoá ở secret SUB_ENC_KEY (máy chủ không lưu `sub` dạng rõ).
ALTER TABLE accounts ADD COLUMN sub_enc BLOB;
-- Lần cuối hỏi kênh trạng thái cho tài khoản quá hạn (mili giây Unix) - hỏi lại tối đa 1 lần/ngày.
ALTER TABLE accounts ADD COLUMN purge_checked_at INTEGER NOT NULL DEFAULT 0;
