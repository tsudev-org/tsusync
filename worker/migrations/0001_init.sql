-- TsuDEV Sync - lược đồ ban đầu (ADR-0001).
-- Máy chủ chỉ giữ BẢN MÃ: không có cột nào chứa bản rõ, khoá hay `sub` gốc.
-- `sub_key` = hex(SHA-256("tsusync|" + sub)); `ns` = `aud` của JWS quyền lợi (client_id của sản phẩm).
-- Mọi thời điểm là mili giây Unix.

CREATE TABLE accounts (
  ns              TEXT    NOT NULL,
  sub_key         TEXT    NOT NULL,
  rev             INTEGER NOT NULL DEFAULT 0,  -- con trỏ rev cuối đã cấp (dùng chung cho records + files)
  data_bytes      INTEGER NOT NULL DEFAULT 0,  -- tính vào hạn mức "dữ liệu" (mặc định 100 MiB)
  file_bytes      INTEGER NOT NULL DEFAULT 0,  -- tính vào hạn mức "tệp" (mặc định 1 GiB)
  pro_until       INTEGER NOT NULL DEFAULT 0,  -- từ JWS mới nhất (theo iat); 0 = chưa từng có Pro
  pro_iat         INTEGER NOT NULL DEFAULT 0,
  lock            TEXT    NOT NULL,            -- thẻ ghi lạc quan: mỗi lần ghi đổi sang giá trị ngẫu nhiên mới
  purge_requested INTEGER NOT NULL DEFAULT 0,  -- 1 = người dùng yêu cầu xoá / đang xoá theo lô
  created_at      INTEGER NOT NULL,
  seen_at         INTEGER NOT NULL,
  PRIMARY KEY (ns, sub_key)
) WITHOUT ROWID;

CREATE INDEX accounts_purge ON accounts (purge_requested, pro_until);

CREATE TABLE records (
  ns         TEXT    NOT NULL,
  sub_key    TEXT    NOT NULL,
  id         TEXT    NOT NULL,                 -- định danh mờ do máy khách chọn (không chứa bản rõ)
  rev        INTEGER NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,       -- bia mộ: payload NULL, vẫn trả khi kéo để xoá trên thiết bị khác
  size       INTEGER NOT NULL,                 -- byte tính hạn mức (payload + id + 64)
  digest     TEXT    NOT NULL,                 -- base64url(SHA-256) để ghi lặp lại không tạo bản sao
  payload    BLOB,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (ns, sub_key, id)
);

CREATE UNIQUE INDEX records_rev ON records (ns, sub_key, rev);

CREATE TABLE files (
  ns         TEXT    NOT NULL,
  sub_key    TEXT    NOT NULL,
  id         TEXT    NOT NULL,
  rev        INTEGER NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  size       INTEGER NOT NULL,                 -- byte bản mã trong R2 (0 khi đã xoá)
  digest     TEXT    NOT NULL,                 -- base64url(SHA-256) của bản mã, R2 kiểm khi ghi
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (ns, sub_key, id)
);

CREATE UNIQUE INDEX files_rev ON files (ns, sub_key, rev);

-- Tổng dung lượng toàn dịch vụ: chặn trước khi chạm hạn mức miễn phí của D1/R2 (ADR-0001 mục 3.6).
CREATE TABLE totals (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  data_bytes INTEGER NOT NULL DEFAULT 0,
  file_bytes INTEGER NOT NULL DEFAULT 0
);
INSERT INTO totals (id) VALUES (1);

-- Giới hạn tần suất ghi theo tài khoản (cửa sổ cố định). Khoá: "<ns>:<sub_key>".
CREATE TABLE rate_limits (
  key          TEXT    PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
) WITHOUT ROWID;
