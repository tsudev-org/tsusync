import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  ABYTES,
  CHUNK_BYTES,
  b64u,
  createKeys,
  decrypt,
  deriveRaw,
  encrypt,
  fromB64u,
  ready,
  TsuSyncCryptoError,
  unlockKeys,
  WeakPasswordError,
  WrongPasswordError,
  type CipherContext,
  type Kind,
} from '../src/index.ts';

/* eslint-disable @typescript-eslint/no-explicit-any */
const v: any = JSON.parse(readFileSync(new URL('../../../conformance/vectors-v1.json', import.meta.url), 'utf8'));
const pattern = (n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + 7) & 0xff);
const FULL = CHUNK_BYTES + ABYTES;
const HEAD = 28;

/** Áp đột biến của `must_fail` - CÙNG ngữ nghĩa với conformance/verify_libsodium.py và test Dart. */
function mutate(src: Uint8Array, m: any): Uint8Array {
  let ct: Uint8Array = Uint8Array.from(src);
  if (m.flip !== undefined) ct[m.flip < 0 ? ct.length + m.flip : m.flip]! ^= 1;
  if (m.truncate !== undefined) ct = ct.subarray(0, ct.length - m.truncate);
  if (m.keep !== undefined) ct = ct.subarray(0, m.keep);
  if (m.drop_last_chunk) {
    const n = Math.max(1, Math.ceil((ct.length - HEAD) / FULL));
    ct = ct.subarray(0, HEAD + (n - 1) * FULL);
  }
  if (m.append_b64 !== undefined) {
    const extra = fromB64u(m.append_b64);
    const next = new Uint8Array(ct.length + extra.length);
    next.set(ct);
    next.set(extra, ct.length);
    ct = next;
  }
  if (m.swap_chunks) {
    const [a, b] = m.swap_chunks as [number, number];
    const ca = ct.slice(HEAD + a * FULL, HEAD + (a + 1) * FULL);
    const cb = ct.slice(HEAD + b * FULL, HEAD + (b + 1) * FULL);
    expect(ca.length).toBe(FULL);
    expect(cb.length).toBe(FULL);
    ct.set(cb, HEAD + a * FULL);
    ct.set(ca, HEAD + b * FULL);
  }
  if (m.set_byte) ct[m.set_byte[0]] = m.set_byte[1];
  return ct;
}

await ready();

describe('vector đối chiếu tsusync-stream-v1', () => {
  it('đúng định dạng', () => expect(v.format).toBe('tsusync-stream-v1'));

  for (const c of v.stream.cases) {
    it(`mở được ${c.name}`, () => {
      const ctx: CipherContext = { namespace: c.namespace, kind: c.kind as Kind, id: c.id };
      const expected = c.plaintext_pattern !== undefined ? pattern(c.plaintext_pattern) : fromB64u(c.plaintext_b64);
      expect(b64u(decrypt(fromB64u(v.stream.data_key), ctx, fromB64u(c.ciphertext)))).toBe(b64u(expected));
    });
  }

  for (const f of v.stream.must_fail) {
    it(`từ chối ${f.name}`, () => {
      const base = v.stream.cases.find((c: any) => c.name === f.base);
      const ctx = { namespace: base.namespace, kind: base.kind, id: base.id, ...(f.mutation.context ?? {}) } as CipherContext;
      const key = fromB64u(f.mutation.key ?? v.stream.data_key);
      expect(() => decrypt(key, ctx, mutate(fromB64u(base.ciphertext), f.mutation))).toThrow(TsuSyncCryptoError);
    });
  }

  for (const c of v.kdf.cases) {
    it(`suy khoá ${c.name}`, () => {
      const r = deriveRaw(c.password, fromB64u(c.salt), c.ops, c.mem);
      expect([b64u(r.dataKey), b64u(r.check)]).toEqual([c.data_key, c.check]);
    });
  }

  for (const c of v.kdf.reject) {
    it(`từ chối KDF ${c.name}`, () => {
      const run = () => deriveRaw(c.password, fromB64u(c.salt), c.ops, c.mem);
      if (c.error === 'weak_password') expect(run).toThrow(WeakPasswordError);
      else expect(run).toThrow(TsuSyncCryptoError);
    });
  }

  for (const c of v.kdf.unlock) {
    it(`mở khoá ${c.name}`, () => {
      if (c.error) expect(() => unlockKeys(c.password, c.params)).toThrow(WrongPasswordError);
      else expect(b64u(unlockKeys(c.password, c.params).dataKey)).toBe(c.data_key);
    });
  }
});

describe('mã hoá khứ hồi', () => {
  const key = fromB64u(v.stream.data_key);
  for (const [kind, n] of [
    ['rec', 0],
    ['rec', 1],
    ['file', CHUNK_BYTES - 1],
    ['file', CHUNK_BYTES],
    ['file', 3 * CHUNK_BYTES + 7],
  ] as const) {
    it(`${kind} ${n} byte`, () => {
      const ctx = { namespace: 'tsudev-test', kind, id: 'x1' } as const;
      const ct = encrypt(key, ctx, pattern(n));
      expect(b64u(decrypt(key, ctx, ct))).toBe(b64u(pattern(n)));
      // Cùng bản rõ ⇒ bản mã khác nhau (header ngẫu nhiên).
      expect(b64u(encrypt(key, ctx, pattern(n)))).not.toBe(b64u(ct));
    });
  }

  it('đệm giấu cỡ bản ghi theo khối 256 B', () => {
    const ctx = { namespace: 'tsudev-test', kind: 'rec', id: 'x1' } as const;
    expect(encrypt(key, ctx, pattern(1)).length).toBe(encrypt(key, ctx, pattern(200)).length);
  });

  it('ngữ cảnh sai định dạng bị từ chối trước khi mã hoá', () => {
    expect(() => encrypt(key, { namespace: 'a b', kind: 'rec', id: 'x' }, pattern(1))).toThrow(TsuSyncCryptoError);
    expect(() => encrypt(key, { namespace: 'ns', kind: 'rec', id: 'tên tệp.pdf' }, pattern(1))).toThrow(TsuSyncCryptoError);
  });

  it('createKeys + unlockKeys khứ hồi, tham số dưới sàn hoặc lạ bị từ chối', () => {
    const k = createKeys('mật khẩu đủ dài 2026', { ops: 2, mem: 19 * 1024 * 1024 });
    expect(b64u(unlockKeys('mật khẩu đủ dài 2026'.normalize('NFD'), JSON.parse(JSON.stringify(k.params))).dataKey)).toBe(
      b64u(k.dataKey),
    );
    expect(() => unlockKeys('mật khẩu đủ dài 2026', { ...k.params, ops: 1 })).toThrow(TsuSyncCryptoError);
    expect(() => unlockKeys('mật khẩu đủ dài 2026', { ...k.params, alg: 'scrypt' })).toThrow(TsuSyncCryptoError);
  });
});
