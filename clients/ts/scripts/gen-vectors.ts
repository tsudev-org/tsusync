/**
 * Sinh `conformance/vectors-v1.json` (ADR-0003). Chạy: `npm run vectors > ../../conformance/vectors-v1.json`.
 *
 * Header secretstream là ngẫu nhiên nên chạy lại cho ra bản mã KHÁC - đó là bình thường. Vector đã commit là hợp đồng:
 * mọi thư viện (TypeScript, Dart, sau này Rust/.NET) và bộ kiểm libsodium độc lập (Python) phải MỞ được đúng các bản mã
 * này, suy ra đúng khoá, và từ chối đúng mọi ca `must_fail`. Chỉ sinh lại khi đổi định dạng (kèm ADR mới).
 */
import { b64u, createKeys, deriveRaw, encrypt, KDF_DEFAULT, KDF_MIN, ready, type CipherContext } from '../src/index.ts';

await ready();

const pattern = (n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + 7) & 0xff);
const key = Uint8Array.from({ length: 32 }, (_, i) => (0xa0 + i) & 0xff);
const otherKey = Uint8Array.from({ length: 32 }, (_, i) => (0x10 + i) & 0xff);
const salt = Uint8Array.from({ length: 16 }, (_, i) => i);
const ns = 'tsudev-test';

type PlainSpec = { plaintext_b64: string } | { plaintext_pattern: number };
const streamCases: (CipherContext & { name: string } & PlainSpec & { ciphertext: string })[] = [];
function addStream(name: string, kind: CipherContext['kind'], id: string, plain: Uint8Array, spec: PlainSpec) {
  const ctx = { namespace: ns, kind, id };
  streamCases.push({ name, ...ctx, ...spec, ciphertext: b64u(encrypt(key, ctx, plain)) });
}
const text = new TextEncoder().encode('{"ghi_chu":"Tiền điện tháng 11","so_tien":1250000}');
addStream('rec-empty', 'rec', 'r0', new Uint8Array(0), { plaintext_b64: '' });
addStream('rec-utf8', 'rec', 'r1', text, { plaintext_b64: b64u(text) });
addStream('rec-pad-255', 'rec', 'r2', pattern(255), { plaintext_pattern: 255 });
addStream('rec-pad-256', 'rec', 'r3', pattern(256), { plaintext_pattern: 256 });
addStream('file-one-chunk-full', 'file', 'f1', pattern(65535), { plaintext_pattern: 65535 });
addStream('file-two-chunks', 'file', 'f2', pattern(65536), { plaintext_pattern: 65536 });
addStream('file-three-chunks', 'file', 'f3', pattern(2 * 65536 + 100), { plaintext_pattern: 2 * 65536 + 100 });

const mustFail = [
  { name: 'flip-header', base: 'rec-utf8', mutation: { flip: 10 } },
  { name: 'flip-mac', base: 'rec-utf8', mutation: { flip: -1 } },
  { name: 'flip-middle-chunk', base: 'file-three-chunks', mutation: { flip: 28 + 65553 + 100 } },
  { name: 'truncate-last-byte', base: 'rec-utf8', mutation: { truncate: 1 } },
  { name: 'drop-last-chunk', base: 'file-three-chunks', mutation: { drop_last_chunk: true } },
  { name: 'drop-last-chunk-2', base: 'file-two-chunks', mutation: { drop_last_chunk: true } },
  { name: 'append-after-final', base: 'file-one-chunk-full', mutation: { append_b64: b64u(new Uint8Array(17)) } },
  { name: 'append-byte', base: 'rec-utf8', mutation: { append_b64: 'AA' } },
  { name: 'swap-chunks', base: 'file-three-chunks', mutation: { swap_chunks: [0, 1] } },
  { name: 'wrong-id', base: 'rec-utf8', mutation: { context: { id: 'r9' } } },
  { name: 'wrong-namespace', base: 'rec-utf8', mutation: { context: { namespace: 'tsudev-khac' } } },
  { name: 'wrong-kind-prefix', base: 'rec-utf8', mutation: { context: { kind: 'file' } } },
  { name: 'wrong-kind-aad', base: 'rec-utf8', mutation: { context: { kind: 'file' }, set_byte: [3, 2] } },
  { name: 'wrong-format-version', base: 'rec-utf8', mutation: { set_byte: [2, 2] } },
  { name: 'wrong-key', base: 'rec-utf8', mutation: { key: b64u(otherKey) } },
  { name: 'too-short', base: 'rec-utf8', mutation: { keep: 44 } },
];

const vi = 'Mật khẩu đồng bộ năm 2026';
const kdfCases = [
  { name: 'vi-nfc', password: vi.normalize('NFC'), ops: KDF_DEFAULT.ops, mem: KDF_DEFAULT.mem },
  { name: 'vi-nfd-same-key', password: vi.normalize('NFD'), ops: KDF_DEFAULT.ops, mem: KDF_DEFAULT.mem },
  { name: 'fullwidth', password: 'ＴＳＵ ｓｙｎｃ ２０２６', ops: KDF_DEFAULT.ops, mem: KDF_DEFAULT.mem },
  { name: 'fullwidth-nfkc-same-key', password: 'TSU sync 2026', ops: KDF_DEFAULT.ops, mem: KDF_DEFAULT.mem },
  { name: 'emoji-10-code-points-min-params', password: '😀'.repeat(10), ops: KDF_MIN.ops, mem: KDF_MIN.mem },
].map((c) => {
  const { dataKey, check } = deriveRaw(c.password, salt, c.ops, c.mem);
  return { ...c, salt: b64u(salt), data_key: b64u(dataKey), check: b64u(check) };
});

const kdfReject = [
  { name: 'weak-9-chars', password: 'ngắn quá!', ops: 3, mem: KDF_DEFAULT.mem, error: 'weak_password' },
  { name: 'weak-9-emoji-18-utf16-units', password: '😀'.repeat(9), ops: 3, mem: KDF_DEFAULT.mem, error: 'weak_password' },
  { name: 'ops-below-floor', password: vi, ops: 1, mem: KDF_DEFAULT.mem, error: 'invalid_params' },
  { name: 'mem-below-floor', password: vi, ops: 3, mem: 18 * 1024 * 1024, error: 'invalid_params' },
  { name: 'ops-above-ceiling', password: vi, ops: 17, mem: KDF_DEFAULT.mem, error: 'invalid_params' },
  { name: 'mem-above-ceiling', password: vi, ops: 3, mem: 1024 * 1024 * 1024 + 1024, error: 'invalid_params' },
].map((c) => ({ ...c, salt: b64u(salt) }));

// Mở khoá bằng tham số đã lưu (muối ngẫu nhiên, lưu nguyên khối JSON như app sẽ lưu).
const created = createKeys(vi, { ops: KDF_MIN.ops, mem: KDF_MIN.mem });
const unlock = [
  { name: 'unlock-ok', params: created.params, password: vi.normalize('NFD'), data_key: b64u(created.dataKey) },
  { name: 'unlock-wrong-password', params: created.params, password: 'Mật khẩu đồng bộ năm 2027', error: 'wrong_password' },
];

const out = {
  format: 'tsusync-stream-v1',
  adr: 'docs/adr/0003-ma-hoa-may-khach-dinh-dang-ts01.md',
  notes: 'base64url không đệm. plaintext_pattern n: byte i = (i*31+7) & 0xff. flip âm = tính từ cuối. Xem ADR-0003 mục 4.',
  stream: { data_key: b64u(key), cases: streamCases, must_fail: mustFail },
  kdf: { cases: kdfCases, reject: kdfReject, unlock },
};
process.stdout.write(JSON.stringify(out, null, 1) + '\n');
