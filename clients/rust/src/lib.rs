//! Mã hoá đầu cuối của TsuDEV Sync - định dạng `TS 01` (ADR-0003). Máy chủ không bao giờ thấy khoá hay bản rõ.
//!
//! Cùng API và ngữ nghĩa với `clients/ts/src/crypto.ts` và `clients/dart/lib/src/crypto.dart`; ba thư viện cùng qua
//! `conformance/vectors-v1.json` và libsodium C độc lập (`conformance/verify_libsodium.py`).
//!
//! - Khoá gốc = Argon2id13(NFKC(mật khẩu đồng bộ), muối 16 B, ≥ 3 lượt / 64 MiB) - cùng thông số qulythuchi ADR-0007.
//! - Khoá dữ liệu = crypto_kdf(gốc, id 1, "TSUSYNC1"); mã kiểm mật khẩu = crypto_kdf(gốc, id 2, "TSUSYNC1", 16 B).
//! - Bản mã = 'T' 'S' 01 <loại> ‖ header secretstream 24 B ‖ các khối secretstream XChaCha20-Poly1305
//!   (bản rõ đã sodium_pad, cắt khối 64 KiB, khối cuối mang TAG_FINAL). AAD mỗi khối = 4 byte đầu ‖ ngữ cảnh.
//!
//! Đổi BẤT KỲ điểm nào ⇒ định dạng mới + ADR mới + vector mới (`conformance/`), dữ liệu cũ vẫn phải đọc được.

use std::fmt;

use dryoc::classic::crypto_kdf::crypto_kdf_derive_from_key;
use dryoc::classic::crypto_pwhash::{PasswordHashAlgorithm, crypto_pwhash};
use dryoc::classic::crypto_secretstream_xchacha20poly1305::{
    Header, State, crypto_secretstream_xchacha20poly1305_init_pull, crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_pull, crypto_secretstream_xchacha20poly1305_push,
};
use dryoc::rng::copy_randombytes;
use serde_json::{Map, Value, json};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const FORMAT_VERSION: u8 = 1;
pub const CHUNK_BYTES: usize = 64 * 1024;
pub const HEADER_BYTES: usize = 24;
pub const ABYTES: usize = 17;
pub const PREFIX_BYTES: usize = 4;
pub const KDF_CONTEXT: &str = "TSUSYNC1";
pub const SALT_BYTES: usize = 16;
pub const MIN_PASSWORD_LENGTH: usize = 10;

/// Tham số Argon2id: số lượt và bộ nhớ (byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfCost {
    pub ops: u64,
    pub mem: u64,
}

/// Mặc định 3 lượt / 64 MiB; sàn khi mở khoá 2 lượt / 19 MiB (OWASP); trần chống máy chủ độc gây cạn bộ nhớ.
pub const KDF_DEFAULT: KdfCost = KdfCost { ops: 3, mem: 64 * 1024 * 1024 };
pub const KDF_MIN: KdfCost = KdfCost { ops: 2, mem: 19 * 1024 * 1024 };
pub const KDF_MAX: KdfCost = KdfCost { ops: 16, mem: 1024 * 1024 * 1024 };

const TAG_MESSAGE: u8 = 0;
const TAG_FINAL: u8 = 3;

/// Lỗi của thư viện. `Crypto` cố ý chung chung - không nói khoá sai hay dữ liệu bị sửa.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Giải mã/mở khoá thất bại, hoặc tham số/ngữ cảnh không hợp lệ.
    Crypto(&'static str),
    /// Mật khẩu đồng bộ ngắn hơn [`MIN_PASSWORD_LENGTH`] ký tự (đếm theo code point sau NFKC).
    WeakPassword,
    /// Mã kiểm mật khẩu không khớp.
    WrongPassword,
}

const GENERIC: &str = "Không mở được dữ liệu mã hoá.";

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Crypto(m) => f.write_str(m),
            Error::WeakPassword => write!(f, "Mật khẩu đồng bộ cần ít nhất {MIN_PASSWORD_LENGTH} ký tự."),
            Error::WrongPassword => f.write_str("Mật khẩu đồng bộ không đúng."),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn fail<T>() -> Result<T> {
    Err(Error::Crypto(GENERIC))
}

// ---------------------------------------------------------------- base64url không đệm (như libsodium + máy chủ)

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url không đệm.
pub fn b64u(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n =
            (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Giải base64url không đệm. Từ chối ký tự lạ, độ dài không thể có và bit thừa khác 0 (như `sodium_base642bin`).
pub fn from_b64u(s: &str) -> Result<Vec<u8>> {
    const BAD: Error = Error::Crypto("Chuỗi base64url không hợp lệ.");
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for ch in s.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(BAD),
        };
        acc = ((acc << 6) | u32::from(v)) & 0xFFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 4 || acc & ((1 << bits) - 1) != 0 {
        return Err(BAD);
    }
    Ok(out)
}

// ---------------------------------------------------------------- suy khoá

/// Mật khẩu chuẩn hoá NFKC - chữ Việt gõ trên iOS/Windows/Linux có thể khác dạng NFC/NFD.
pub fn normalize_password(password: &str) -> Result<String> {
    let n: String = password.nfkc().collect();
    if n.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(Error::WeakPassword);
    }
    Ok(n)
}

fn check_range(ops: u64, mem: u64) -> Result<()> {
    if ops < KDF_MIN.ops || mem < KDF_MIN.mem {
        return Err(Error::Crypto("Tham số KDF yếu hơn mức tối thiểu."));
    }
    if ops > KDF_MAX.ops || mem > KDF_MAX.mem {
        return Err(Error::Crypto("Tham số KDF vượt trần."));
    }
    Ok(())
}

/// Khoá dữ liệu 32 B - giữ trong bộ nhớ, KHÔNG gửi đi. Tự xoá về 0 khi rời phạm vi.
pub type DataKey = Zeroizing<[u8; 32]>;

/// Kết quả suy khoá thô.
pub struct Derived {
    pub data_key: DataKey,
    pub check: [u8; 16],
}

/// Suy khoá - hàm thuần, dùng cho cả tạo mới, mở khoá và vector đối chiếu.
pub fn derive_raw(password: &str, salt: &[u8], ops: u64, mem: u64) -> Result<Derived> {
    check_range(ops, mem)?;
    if salt.len() != SALT_BYTES {
        return Err(Error::Crypto("Muối KDF phải dài 16 byte."));
    }
    let pw = Zeroizing::new(normalize_password(password)?.into_bytes());
    let mut root = Zeroizing::new([0u8; 32]);
    let mem = usize::try_from(mem).map_err(|_| Error::Crypto("Tham số KDF vượt trần."))?;
    crypto_pwhash(&mut root[..], &pw, salt, ops, mem, PasswordHashAlgorithm::Argon2id13)
        .map_err(|_| Error::Crypto("Không suy được khoá (thiếu bộ nhớ?)."))?;
    let ctx: [u8; 8] = *b"TSUSYNC1";
    let mut data_key: DataKey = Zeroizing::new([0u8; 32]);
    let mut check = [0u8; 16];
    crypto_kdf_derive_from_key(&mut data_key[..], 1, &ctx, &root).map_err(|_| Error::Crypto(GENERIC))?;
    crypto_kdf_derive_from_key(&mut check, 2, &ctx, &root).map_err(|_| Error::Crypto(GENERIC))?;
    Ok(Derived { data_key, check })
}

/// Tham số KDF lưu kèm dữ liệu (không bí mật). `check` cho biết mật khẩu đúng hay sai mà không cần giải mã thử.
/// JSON: `{"v":1,"alg":"argon2id13","salt":..,"ops":..,"mem":..,"check":..}` (thứ tự khoá như TypeScript/Dart).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub salt: String,
    pub ops: u64,
    pub mem: u64,
    pub check: String,
}

impl KdfParams {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("v".into(), json!(1));
        m.insert("alg".into(), json!("argon2id13"));
        m.insert("salt".into(), json!(self.salt));
        m.insert("ops".into(), json!(self.ops));
        m.insert("mem".into(), json!(self.mem));
        m.insert("check".into(), json!(self.check));
        Value::Object(m)
    }
}

/// Đọc tham số KDF từ JSON không tin cậy (máy chủ trả về).
pub fn parse_kdf_params(raw: &Value) -> Result<KdfParams> {
    let o = raw.as_object().ok_or(Error::Crypto("Tham số KDF không hỗ trợ."))?;
    if o.get("v").and_then(Value::as_u64) != Some(1) || o.get("alg").and_then(Value::as_str) != Some("argon2id13") {
        return Err(Error::Crypto("Tham số KDF không hỗ trợ."));
    }
    let bad = Error::Crypto("Tham số KDF không hợp lệ.");
    let s = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_owned);
    let n = |k: &str| o.get(k).and_then(Value::as_u64);
    let (Some(salt), Some(check), Some(ops), Some(mem)) = (s("salt"), s("check"), n("ops"), n("mem")) else {
        return Err(bad);
    };
    check_range(ops, mem)?;
    Ok(KdfParams { salt, ops, mem, check })
}

/// Khoá đồng bộ đã mở.
pub struct SyncKeys {
    pub data_key: DataKey,
    pub params: KdfParams,
}

/// Tạo khoá mới cho tài khoản đồng bộ (lần đầu bật đồng bộ trên thiết bị đầu tiên). Mặc định [`KDF_DEFAULT`].
pub fn create_keys(password: &str, cost: Option<KdfCost>) -> Result<SyncKeys> {
    let KdfCost { ops, mem } = cost.unwrap_or(KDF_DEFAULT);
    let mut salt = [0u8; SALT_BYTES];
    copy_randombytes(&mut salt);
    let d = derive_raw(password, &salt, ops, mem)?;
    let params = KdfParams { salt: b64u(&salt), ops, mem, check: b64u(&d.check) };
    Ok(SyncKeys { data_key: d.data_key, params })
}

/// Mở khoá trên thiết bị khác bằng tham số đã lưu (JSON). Sai mật khẩu ⇒ [`Error::WrongPassword`].
pub fn unlock_keys(password: &str, params: &Value) -> Result<SyncKeys> {
    let p = parse_kdf_params(params)?;
    let d = derive_raw(password, &from_b64u(&p.salt)?, p.ops, p.mem)?;
    let expected = from_b64u(&p.check)?;
    if !ct_eq(&expected, &d.check) {
        return Err(Error::WrongPassword);
    }
    Ok(SyncKeys { data_key: d.data_key, params: p })
}

/// So sánh thời gian hằng (như `sodium_memcmp`); độ dài khác nhau ⇒ false ngay (độ dài không bí mật).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let d = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(d) == 0
}

// ---------------------------------------------------------------- mã hoá

/// Loại bản mã - nằm trong byte thứ tư của tiền tố và trong ngữ cảnh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Rec,
    File,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Rec => "rec",
            Kind::File => "file",
        }
    }
    pub fn from_name(s: &str) -> Option<Kind> {
        match s {
            "rec" => Some(Kind::Rec),
            "file" => Some(Kind::File),
            _ => None,
        }
    }
    fn byte(self) -> u8 {
        match self {
            Kind::Rec => 1,
            Kind::File => 2,
        }
    }
    /// Khối đệm giấu cỡ bản rõ: bản ghi 256 B, tệp 4096 B.
    pub fn pad_block(self) -> usize {
        match self {
            Kind::Rec => 256,
            Kind::File => 4096,
        }
    }
}

/// Ngữ cảnh gắn vào AAD: bản mã chỉ mở được đúng sản phẩm + loại + định danh đã tạo ra nó (chống máy chủ tráo bản ghi).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherContext {
    pub namespace: String,
    pub kind: Kind,
    pub id: String,
}

impl CipherContext {
    pub fn new(namespace: impl Into<String>, kind: Kind, id: impl Into<String>) -> Self {
        CipherContext { namespace: namespace.into(), kind, id: id.into() }
    }
}

/// `^[A-Za-z0-9._~:-]{1,128}$`
fn safe(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b':' | b'-'))
}

fn prefix(kind: Kind) -> [u8; PREFIX_BYTES] {
    [0x54, 0x53, FORMAT_VERSION, kind.byte()]
}

fn aad(ctx: &CipherContext) -> Result<Vec<u8>> {
    if !safe(&ctx.namespace) || !safe(&ctx.id) {
        return Err(Error::Crypto("Ngữ cảnh mã hoá không hợp lệ."));
    }
    let mut out = prefix(ctx.kind).to_vec();
    out.extend_from_slice(format!("tsusync|v1|{}|{}|{}", ctx.namespace, ctx.kind.name(), ctx.id).as_bytes());
    Ok(out)
}

/// `sodium_pad`: thêm 0x80 rồi các byte 0 tới bội số kế tiếp của `block` (luôn thêm ít nhất 1 byte).
fn pad(plain: &[u8], block: usize) -> Zeroizing<Vec<u8>> {
    let len = plain.len() + block - plain.len() % block;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(plain);
    out.push(0x80);
    out.resize(len, 0);
    out
}

/// `sodium_unpad` - cùng vòng thời gian hằng của libsodium. Trả độ dài bản rõ.
fn unpad(buf: &[u8], block: usize) -> Option<usize> {
    if buf.len() < block || block == 0 {
        return None;
    }
    let (mut acc, mut valid, mut pad_len) = (0usize, 0usize, 0usize);
    for i in 0..block {
        let c = usize::from(buf[buf.len() - 1 - i]);
        let is_barrier = ((acc.wrapping_sub(1) & pad_len.wrapping_sub(1) & (c ^ 0x80).wrapping_sub(1)) >> 8) & 1;
        acc |= c;
        pad_len |= i & is_barrier.wrapping_neg();
        valid |= is_barrier;
    }
    (valid == 1).then(|| buf.len() - 1 - pad_len)
}

/// Mã hoá một bản ghi/tệp. Mỗi lần gọi ra bản mã khác nhau (header ngẫu nhiên).
pub fn encrypt(data_key: &[u8; 32], ctx: &CipherContext, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ad = aad(ctx)?;
    let padded = pad(plaintext, ctx.kind.pad_block());
    let mut state = State::new();
    let mut header: Header = [0u8; HEADER_BYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, data_key);
    let chunks = padded.len().div_ceil(CHUNK_BYTES);
    let mut out = Vec::with_capacity(PREFIX_BYTES + HEADER_BYTES + padded.len() + chunks * ABYTES);
    out.extend_from_slice(&prefix(ctx.kind));
    out.extend_from_slice(&header);
    for (i, chunk) in padded.chunks(CHUNK_BYTES).enumerate() {
        let tag = if i == chunks - 1 { TAG_FINAL } else { TAG_MESSAGE };
        let pos = out.len();
        out.resize(pos + chunk.len() + ABYTES, 0);
        crypto_secretstream_xchacha20poly1305_push(&mut state, &mut out[pos..], chunk, Some(&ad), tag)
            .map_err(|_| Error::Crypto(GENERIC))?;
    }
    Ok(out)
}

/// Giải mã. Mọi sai lệch (khoá, ngữ cảnh, cắt cụt, nối thêm, tráo khối, đệm) ⇒ [`Error::Crypto`] chung.
pub fn decrypt(data_key: &[u8; 32], ctx: &CipherContext, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let ad = aad(ctx)?;
    let head = PREFIX_BYTES + HEADER_BYTES;
    if ciphertext.len() < head + ABYTES || ciphertext[..PREFIX_BYTES] != prefix(ctx.kind) {
        return fail();
    }
    let body = &ciphertext[head..];
    let full = CHUNK_BYTES + ABYTES;
    let n = body.len().div_ceil(full).max(1);
    // Khối cuối phải có ít nhất ABYTES; mọi khối trước đó phải đầy.
    if body.len() - (n - 1) * full < ABYTES {
        return fail();
    }
    let mut header: Header = [0u8; HEADER_BYTES];
    header.copy_from_slice(&ciphertext[PREFIX_BYTES..head]);
    let mut state = State::new();
    crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, data_key);
    let mut out = Zeroizing::new(vec![0u8; body.len() - n * ABYTES]);
    let mut pos = 0;
    for (i, chunk) in body.chunks(full).enumerate() {
        let mut tag = 0u8;
        let m = crypto_secretstream_xchacha20poly1305_pull(&mut state, &mut out[pos..], &mut tag, chunk, Some(&ad))
            .or_else(|_| fail())?;
        // TAG_FINAL đúng ở khối cuối và CHỈ ở đó: chống cắt cụt và chống nối thêm.
        if (tag == TAG_FINAL) != (i == n - 1) || (tag != TAG_FINAL && tag != TAG_MESSAGE) {
            return fail();
        }
        pos += m;
    }
    let len = unpad(&out[..pos], ctx.kind.pad_block()).ok_or(Error::Crypto(GENERIC))?;
    // `out` (Zeroizing) xoá phần đệm + bản rõ trung gian khi rời phạm vi.
    Ok(out[..len].to_vec())
}
