/**
 * Mã hoá đầu cuối của TsuDEV Sync - định dạng `TS 01` (ADR-0003). Máy chủ không bao giờ thấy khoá hay bản rõ.
 *
 * - Khoá gốc = Argon2id13(NFKC(mật khẩu đồng bộ), muối 16 B, ≥ 3 lượt / 64 MiB) - cùng thông số qulythuchi ADR-0007.
 * - Khoá dữ liệu = crypto_kdf(gốc, id 1, "TSUSYNC1"); mã kiểm mật khẩu = crypto_kdf(gốc, id 2, "TSUSYNC1", 16 B).
 * - Bản mã = 'T' 'S' 01 <loại> ‖ header secretstream 24 B ‖ các khối secretstream XChaCha20-Poly1305
 *   (bản rõ đã sodium_pad, cắt khối 64 KiB, khối cuối mang TAG_FINAL). AAD mỗi khối = 4 byte đầu ‖ ngữ cảnh.
 *
 * Đổi BẤT KỲ điểm nào ⇒ định dạng mới + ADR mới + vector mới (`conformance/`), dữ liệu cũ vẫn phải đọc được.
 */
import sodium from 'libsodium-wrappers-sumo';

export const FORMAT_VERSION = 1;
export const CHUNK_BYTES = 64 * 1024;
export const HEADER_BYTES = 24;
export const ABYTES = 17;
export const PREFIX_BYTES = 4;
export const KDF_CONTEXT = 'TSUSYNC1';
export const SALT_BYTES = 16;
export const MIN_PASSWORD_LENGTH = 10;

/** Mặc định 3 lượt / 64 MiB; sàn khi mở khoá 2 lượt / 19 MiB (OWASP); trần chống máy chủ độc gây cạn bộ nhớ. */
export const KDF_DEFAULT = { ops: 3, mem: 64 * 1024 * 1024 } as const;
export const KDF_MIN = { ops: 2, mem: 19 * 1024 * 1024 } as const;
export const KDF_MAX = { ops: 16, mem: 1024 * 1024 * 1024 } as const;

/** Loại bản mã - nằm trong byte thứ tư của tiền tố và trong ngữ cảnh. */
export type Kind = 'rec' | 'file';
const KIND_BYTE: Record<Kind, number> = { rec: 1, file: 2 };
/** Khối đệm giấu cỡ bản rõ: bản ghi 256 B, tệp 4096 B. */
export const PAD_BLOCK: Record<Kind, number> = { rec: 256, file: 4096 };

const TAG_MESSAGE = 0;
const TAG_FINAL = 3;
const SAFE = /^[A-Za-z0-9._~:-]{1,128}$/;

/** Giải mã/mở khoá thất bại. Thông điệp cố ý chung - không nói khoá sai hay dữ liệu bị sửa. */
export class TsuSyncCryptoError extends Error {
  constructor(message = 'Không mở được dữ liệu mã hoá.') {
    super(message);
    this.name = 'TsuSyncCryptoError';
  }
}
export class WeakPasswordError extends Error {
  constructor() {
    super(`Mật khẩu đồng bộ cần ít nhất ${MIN_PASSWORD_LENGTH} ký tự.`);
    this.name = 'WeakPasswordError';
  }
}
export class WrongPasswordError extends Error {
  constructor() {
    super('Mật khẩu đồng bộ không đúng.');
    this.name = 'WrongPasswordError';
  }
}

/** Gọi một lần trước mọi hàm khác (nạp WASM). */
export async function ready(): Promise<void> {
  await sodium.ready;
}

/** base64url không đệm (như máy chủ). Không dùng `Buffer` để chạy được cả trên trình duyệt. */
export function b64u(bytes: Uint8Array): string {
  return bytes.length === 0 ? '' : sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}
export function fromB64u(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new TsuSyncCryptoError('Chuỗi base64url không hợp lệ.');
  if (s.length === 0) return new Uint8Array(0);
  try {
    return sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);
  } catch {
    throw new TsuSyncCryptoError('Chuỗi base64url không hợp lệ.');
  }
}

/** Mật khẩu chuẩn hoá NFKC - chữ Việt gõ trên iOS/Windows/Linux có thể khác dạng NFC/NFD. */
export function normalizePassword(password: string): string {
  const n = password.normalize('NFKC');
  if ([...n].length < MIN_PASSWORD_LENGTH) throw new WeakPasswordError();
  return n;
}

/** Tham số KDF lưu kèm dữ liệu (không bí mật). `check` cho biết mật khẩu đúng hay sai mà không cần giải mã thử. */
export interface KdfParams {
  v: 1;
  alg: 'argon2id13';
  salt: string;
  ops: number;
  mem: number;
  check: string;
}

export interface SyncKeys {
  /** Khoá dữ liệu 32 B - giữ trong bộ nhớ, KHÔNG gửi đi. */
  dataKey: Uint8Array;
  params: KdfParams;
}

function checkRange(ops: number, mem: number): void {
  if (!Number.isSafeInteger(ops) || !Number.isSafeInteger(mem)) throw new TsuSyncCryptoError('Tham số KDF không hợp lệ.');
  if (ops < KDF_MIN.ops || mem < KDF_MIN.mem) throw new TsuSyncCryptoError('Tham số KDF yếu hơn mức tối thiểu.');
  if (ops > KDF_MAX.ops || mem > KDF_MAX.mem) throw new TsuSyncCryptoError('Tham số KDF vượt trần.');
}

/** Suy khoá - hàm thuần, dùng cho cả tạo mới, mở khoá và vector đối chiếu. */
export function deriveRaw(password: string, salt: Uint8Array, ops: number, mem: number): { dataKey: Uint8Array; check: Uint8Array } {
  checkRange(ops, mem);
  if (salt.length !== SALT_BYTES) throw new TsuSyncCryptoError('Muối KDF phải dài 16 byte.');
  const pw = new TextEncoder().encode(normalizePassword(password));
  const root = sodium.crypto_pwhash(32, pw, salt, ops, mem, sodium.crypto_pwhash_ALG_ARGON2ID13);
  try {
    return {
      dataKey: sodium.crypto_kdf_derive_from_key(32, 1, KDF_CONTEXT, root),
      check: sodium.crypto_kdf_derive_from_key(16, 2, KDF_CONTEXT, root),
    };
  } finally {
    sodium.memzero(root);
    sodium.memzero(pw);
  }
}

/** Tạo khoá mới cho tài khoản đồng bộ (lần đầu bật đồng bộ trên thiết bị đầu tiên). */
export function createKeys(password: string, opts: { ops?: number; mem?: number } = {}): SyncKeys {
  const ops = opts.ops ?? KDF_DEFAULT.ops;
  const mem = opts.mem ?? KDF_DEFAULT.mem;
  const salt = sodium.randombytes_buf(SALT_BYTES);
  const { dataKey, check } = deriveRaw(password, salt, ops, mem);
  return { dataKey, params: { v: 1, alg: 'argon2id13', salt: b64u(salt), ops, mem, check: b64u(check) } };
}

/** Mở khoá trên thiết bị khác bằng tham số đã lưu. Sai mật khẩu ⇒ `WrongPasswordError`. */
export function unlockKeys(password: string, params: unknown): SyncKeys {
  const p = parseKdfParams(params);
  const { dataKey, check } = deriveRaw(password, fromB64u(p.salt), p.ops, p.mem);
  const expected = fromB64u(p.check);
  if (expected.length !== check.length || !sodium.memcmp(expected, check)) {
    sodium.memzero(dataKey);
    throw new WrongPasswordError();
  }
  return { dataKey, params: p };
}

export function parseKdfParams(raw: unknown): KdfParams {
  const o = raw as Partial<KdfParams> | null;
  if (!o || typeof o !== 'object' || o.v !== 1 || o.alg !== 'argon2id13') throw new TsuSyncCryptoError('Tham số KDF không hỗ trợ.');
  if (typeof o.salt !== 'string' || typeof o.check !== 'string' || typeof o.ops !== 'number' || typeof o.mem !== 'number') {
    throw new TsuSyncCryptoError('Tham số KDF không hợp lệ.');
  }
  checkRange(o.ops, o.mem);
  return { v: 1, alg: 'argon2id13', salt: o.salt, ops: o.ops, mem: o.mem, check: o.check };
}

/** Ngữ cảnh gắn vào AAD: bản mã chỉ mở được đúng sản phẩm + loại + định danh đã tạo ra nó (chống máy chủ tráo bản ghi). */
export interface CipherContext {
  namespace: string;
  kind: Kind;
  id: string;
}

function prefix(kind: Kind): Uint8Array {
  return Uint8Array.of(0x54, 0x53, FORMAT_VERSION, KIND_BYTE[kind]);
}

function aad(ctx: CipherContext): Uint8Array {
  if (!SAFE.test(ctx.namespace) || !SAFE.test(ctx.id) || !(ctx.kind in KIND_BYTE)) {
    throw new TsuSyncCryptoError('Ngữ cảnh mã hoá không hợp lệ.');
  }
  const text = new TextEncoder().encode(`tsusync|v1|${ctx.namespace}|${ctx.kind}|${ctx.id}`);
  const out = new Uint8Array(PREFIX_BYTES + text.length);
  out.set(prefix(ctx.kind));
  out.set(text, PREFIX_BYTES);
  return out;
}

export function encrypt(dataKey: Uint8Array, ctx: CipherContext, plaintext: Uint8Array): Uint8Array {
  const ad = aad(ctx);
  const padded = sodium.pad(plaintext, PAD_BLOCK[ctx.kind]);
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(dataKey);
  const parts: Uint8Array[] = [prefix(ctx.kind), header];
  for (let off = 0; ; off += CHUNK_BYTES) {
    const last = off + CHUNK_BYTES >= padded.length;
    const chunk = padded.subarray(off, Math.min(off + CHUNK_BYTES, padded.length));
    parts.push(sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, ad, last ? TAG_FINAL : TAG_MESSAGE));
    if (last) break;
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

export function decrypt(dataKey: Uint8Array, ctx: CipherContext, ciphertext: Uint8Array): Uint8Array {
  const ad = aad(ctx);
  const head = PREFIX_BYTES + HEADER_BYTES;
  if (ciphertext.length < head + ABYTES) throw new TsuSyncCryptoError();
  const expected = prefix(ctx.kind);
  for (let i = 0; i < PREFIX_BYTES; i++) if (ciphertext[i] !== expected[i]) throw new TsuSyncCryptoError();
  const body = ciphertext.subarray(head);
  const full = CHUNK_BYTES + ABYTES;
  const n = Math.max(1, Math.ceil(body.length / full));
  // Khối cuối phải có ít nhất ABYTES; mọi khối trước đó phải đầy.
  if (body.length - (n - 1) * full < ABYTES) throw new TsuSyncCryptoError();
  let state;
  try {
    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(ciphertext.subarray(PREFIX_BYTES, head), dataKey);
  } catch {
    throw new TsuSyncCryptoError();
  }
  const out = new Uint8Array(n * CHUNK_BYTES);
  let pos = 0;
  for (let i = 0; i < n; i++) {
    const chunk = body.subarray(i * full, Math.min((i + 1) * full, body.length));
    let r: { message: Uint8Array; tag: number } | false;
    try {
      r = sodium.crypto_secretstream_xchacha20poly1305_pull(state, chunk, ad);
    } catch {
      throw new TsuSyncCryptoError();
    }
    if (!r) throw new TsuSyncCryptoError();
    // TAG_FINAL đúng ở khối cuối và CHỈ ở đó: chống cắt cụt và chống nối thêm.
    if ((r.tag === TAG_FINAL) !== (i === n - 1) || (r.tag !== TAG_FINAL && r.tag !== TAG_MESSAGE)) throw new TsuSyncCryptoError();
    out.set(r.message, pos);
    pos += r.message.length;
  }
  try {
    return sodium.unpad(out.subarray(0, pos), PAD_BLOCK[ctx.kind]);
  } catch {
    throw new TsuSyncCryptoError();
  }
}
