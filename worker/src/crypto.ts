const enc = new TextEncoder();

export function b64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Giải base64url nghiêm ngặt (không đệm, đúng bảng chữ). Sai ⇒ null. */
export function fromB64url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return b64url(out) === s ? out : null;
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const buf = typeof data === 'string' ? enc.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}

export const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

export function randomToken(bytes = 16): string {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

let subKeyCache: { raw: string; key: CryptoKey } | null = null;

async function subEncKey(raw: string | undefined): Promise<CryptoKey | null> {
  if (!raw) return null;
  if (subKeyCache?.raw === raw) return subKeyCache.key;
  const bytes = fromB64url(raw);
  if (bytes?.length !== 32) return null;
  const key = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  subKeyCache = { raw, key };
  return key;
}

/**
 * Mã hoá `sub` (AES-256-GCM, nonce 96 bit ngẫu nhiên, AAD = không gian tên) để hỏi lại tsudev.com trước khi xoá
 * (ADR-0002). Kết quả = nonce || bản mã. Thiếu/sai `SUB_ENC_KEY` ⇒ null (không lưu được ⇒ không tự xoá được).
 */
export async function encryptSub(raw: string | undefined, ns: string, sub: string): Promise<Uint8Array | null> {
  const key = await subEncKey(raw);
  if (!key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(ns) }, key, enc.encode(sub)));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return out;
}

export async function decryptSub(raw: string | undefined, ns: string, blob: ArrayBuffer | null): Promise<string | null> {
  const key = await subEncKey(raw);
  if (!key || !blob || blob.byteLength < 12 + 16 + 1) return null;
  const b = new Uint8Array(blob);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12), additionalData: enc.encode(ns) }, key, b.slice(12));
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}
