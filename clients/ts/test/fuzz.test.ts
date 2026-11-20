import { beforeAll, describe, expect, it } from 'vitest';
import {
  ABYTES,
  CHUNK_BYTES,
  b64u,
  decrypt,
  encrypt,
  fromB64u,
  parseKdfParams,
  ready,
  TsuSyncCryptoError,
  type CipherContext,
} from '../src/index.ts';

/**
 * Fuzz đột biến có hạt giống cố định (lặp lại được trong CI): mọi đầu vào KHÔNG tin cậy mà thư viện nhận từ máy chủ
 * (bản mã, tham số KDF, chuỗi base64url) chỉ được trả đúng bản gốc hoặc ném TsuSyncCryptoError - không lỗi nào khác,
 * không bao giờ trả bản rõ khác bản gốc.
 */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = rng(0x7a5c);
const int = (n: number) => Math.floor(rand() * n);
const bytes = (n: number) => Uint8Array.from({ length: n }, () => int(256));

const key = bytes(32);
const ctx: CipherContext = { namespace: 'fuzz', kind: 'rec', id: 'r-1' };
const fileCtx: CipherContext = { namespace: 'fuzz', kind: 'file', id: 'f-1' };

function mutate(src: Uint8Array): Uint8Array {
  const ct = Uint8Array.from(src);
  switch (int(6)) {
    case 0: {
      const i = int(ct.length);
      ct[i]! ^= 1 << int(8);
      return ct;
    }
    case 1:
      return ct.subarray(0, int(ct.length));
    case 2: {
      const out = new Uint8Array(ct.length + 1 + int(64));
      out.set(ct);
      out.set(bytes(out.length - ct.length), ct.length);
      return out;
    }
    case 3: {
      const i = int(ct.length);
      const n = 1 + int(Math.min(32, ct.length - i));
      ct.set(bytes(n).subarray(0, ct.length - i), i);
      return ct;
    }
    case 4: {
      const i = int(ct.length);
      return Uint8Array.from([...ct.subarray(0, i), ...ct.subarray(i + 1 + int(16))]);
    }
    default: {
      // Đảo hai khối 64 KiB (bản mã nhiều khối) hoặc lật byte trong tiền tố/header.
      const full = CHUNK_BYTES + ABYTES;
      if (ct.length > 28 + 2 * full) {
        const a = ct.slice(28, 28 + full);
        ct.copyWithin(28, 28 + full, 28 + 2 * full);
        ct.set(a, 28 + full);
      } else {
        ct[int(28)]! ^= 0xff;
      }
      return ct;
    }
  }
}

function expectRejectOrOriginal(fn: () => Uint8Array, original: Uint8Array): void {
  let out: Uint8Array;
  try {
    out = fn();
  } catch (e) {
    expect(e).toBeInstanceOf(TsuSyncCryptoError);
    return;
  }
  expect(b64u(out)).toBe(b64u(original));
}

beforeAll(ready);

describe('fuzz decrypt', () => {
  it('bản mã bị đột biến chỉ bị từ chối (rec, nhiều kích thước)', () => {
    for (const size of [0, 1, 255, 256, 3000]) {
      const pt = bytes(size);
      const ct = encrypt(key, ctx, pt);
      for (let i = 0; i < 400; i++) {
        const m = mutate(ct);
        if (m.length === ct.length && m.every((b, j) => b === ct[j])) continue;
        expect(() => decrypt(key, ctx, m)).toThrow(TsuSyncCryptoError);
      }
    }
  });

  it('bản mã tệp nhiều khối bị đột biến chỉ bị từ chối', () => {
    const pt = bytes(2 * CHUNK_BYTES + 1234);
    const ct = encrypt(key, fileCtx, pt);
    for (let i = 0; i < 150; i++) {
      const m = mutate(ct);
      if (m.length === ct.length && m.every((b, j) => b === ct[j])) continue;
      expect(() => decrypt(key, fileCtx, m)).toThrow(TsuSyncCryptoError);
    }
  });

  it('bản mã đúng chỉ mở được với đúng khoá và đúng ngữ cảnh', () => {
    const pt = bytes(100);
    const ct = encrypt(key, ctx, pt);
    expectRejectOrOriginal(() => decrypt(key, ctx, ct), pt);
    for (let i = 0; i < 100; i++) {
      const other = bytes(32);
      expect(() => decrypt(other, ctx, ct)).toThrow(TsuSyncCryptoError);
    }
    for (const c of [
      { ...ctx, namespace: 'fuzz2' },
      { ...ctx, id: 'r-2' },
      { ...ctx, kind: 'file' as const },
    ]) {
      expect(() => decrypt(key, c, ct)).toThrow(TsuSyncCryptoError);
    }
  });

  it('chuỗi byte ngẫu nhiên chỉ bị từ chối', () => {
    for (let i = 0; i < 2000; i++) {
      const junk = bytes(int(200));
      if (i % 2 === 0 && junk.length >= 4) junk.set([0x54, 0x53, 1, 1]);
      expect(() => decrypt(key, ctx, junk)).toThrow(TsuSyncCryptoError);
    }
  });
});

describe('fuzz tham số KDF và base64url', () => {
  const values = [
    undefined,
    null,
    true,
    0,
    -1,
    1,
    2,
    3,
    19 * 1024 * 1024,
    64 * 1024 * 1024,
    2 ** 31,
    2 ** 53,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    '',
    'argon2id13',
    'AAAA',
    '1',
    [],
    {},
  ];
  const pick = () => values[int(values.length)];

  it('đối tượng ngẫu nhiên: trả tham số trong khoảng cho phép hoặc ném TsuSyncCryptoError', () => {
    for (let i = 0; i < 3000; i++) {
      const raw: Record<string, unknown> = {};
      for (const k of ['v', 'alg', 'salt', 'ops', 'mem', 'check']) if (rand() < 0.85) raw[k] = pick();
      if (rand() < 0.5) raw.v = 1;
      if (rand() < 0.5) raw.alg = 'argon2id13';
      let p;
      try {
        p = parseKdfParams(i % 50 === 0 ? pick() : raw);
      } catch (e) {
        expect(e).toBeInstanceOf(TsuSyncCryptoError);
        continue;
      }
      expect(Number.isSafeInteger(p.ops) && p.ops >= 2 && p.ops <= 16).toBe(true);
      expect(Number.isSafeInteger(p.mem) && p.mem >= 19 * 1024 * 1024 && p.mem <= 1024 * 1024 * 1024).toBe(true);
    }
  });

  it('chuỗi ngẫu nhiên: giải được thì mã lại đúng chuỗi, không thì ném TsuSyncCryptoError', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/ .á\u0000';
    for (let i = 0; i < 3000; i++) {
      const s = Array.from({ length: int(40) }, () => alphabet[int(alphabet.length)]).join('');
      let out: Uint8Array;
      try {
        out = fromB64u(s);
      } catch (e) {
        expect(e).toBeInstanceOf(TsuSyncCryptoError);
        continue;
      }
      expect(b64u(out)).toBe(s);
    }
  });
});
