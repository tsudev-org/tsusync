#!/usr/bin/env python3
"""Kiểm vector TsuDEV Sync (ADR-0003) bằng libsodium C của hệ điều hành qua ctypes - cài đặt độc lập thứ ba,
không dùng chung dòng mã nào với thư viện TypeScript hay Dart.

Chạy: python3 -I conformance/verify_libsodium.py conformance/vectors-v1.json [tệp vector khác ...]
Tệp do thư viện Dart/TypeScript vừa mã hoá (cùng khuôn) cũng kiểm bằng lệnh này.
"""
import base64
import ctypes
import ctypes.util
import json
import sys
import unicodedata

lib_name = ctypes.util.find_library("sodium") or "libsodium.so.23"
na = ctypes.CDLL(lib_name)
na.sodium_version_string.restype = ctypes.c_char_p
if na.sodium_init() < 0:
    raise SystemExit("sodium_init thất bại")

CHUNK = 64 * 1024
HEADER = na.crypto_secretstream_xchacha20poly1305_headerbytes()
ABYTES = na.crypto_secretstream_xchacha20poly1305_abytes()
STATE = na.crypto_secretstream_xchacha20poly1305_statebytes()
TAG_FINAL = na.crypto_secretstream_xchacha20poly1305_tag_final()
TAG_MESSAGE = na.crypto_secretstream_xchacha20poly1305_tag_message()
ALG = na.crypto_pwhash_alg_argon2id13()
assert (HEADER, ABYTES, TAG_FINAL, TAG_MESSAGE) == (24, 17, 3, 0)
PAD = {"rec": 256, "file": 4096}
KIND = {"rec": 1, "file": 2}
KDF_MIN, KDF_MAX = (2, 19 << 20), (16, 1 << 30)


class Fail(Exception):
    pass


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pattern(n):
    return bytes((i * 31 + 7) & 0xFF for i in range(n))


def derive(password, salt, ops, mem):
    if not (KDF_MIN[0] <= ops <= KDF_MAX[0] and KDF_MIN[1] <= mem <= KDF_MAX[1]):
        raise Fail("invalid_params")
    pw = unicodedata.normalize("NFKC", password)
    if len(pw) < 10:  # Python đếm theo code point - đúng quy ước ADR-0003.
        raise Fail("weak_password")
    pw = pw.encode()
    root = ctypes.create_string_buffer(32)
    if na.crypto_pwhash(root, ctypes.c_ulonglong(32), pw, ctypes.c_ulonglong(len(pw)), salt,
                        ctypes.c_ulonglong(ops), ctypes.c_size_t(mem), ctypes.c_int(ALG)) != 0:
        raise SystemExit("crypto_pwhash hết bộ nhớ")
    out = []
    for sub_id, n in ((1, 32), (2, 16)):
        sub = ctypes.create_string_buffer(n)
        assert na.crypto_kdf_derive_from_key(sub, ctypes.c_size_t(n), ctypes.c_uint64(sub_id), b"TSUSYNC1", root) == 0
        out.append(sub.raw)
    return out


def decrypt(key, ns, kind, rid, ct):
    prefix = bytes([0x54, 0x53, 1, KIND[kind]])
    aad = prefix + f"tsusync|v1|{ns}|{kind}|{rid}".encode()
    if len(ct) < 4 + HEADER + ABYTES or ct[:4] != prefix:
        raise Fail("prefix")
    body = ct[4 + HEADER:]
    full = CHUNK + ABYTES
    n = max(1, -(-len(body) // full))
    if len(body) - (n - 1) * full < ABYTES:
        raise Fail("length")
    st = ctypes.create_string_buffer(STATE)
    if na.crypto_secretstream_xchacha20poly1305_init_pull(st, ct[4:4 + HEADER], key) != 0:
        raise Fail("header")
    out = bytearray()
    for i in range(n):
        c = body[i * full:(i + 1) * full]
        m = ctypes.create_string_buffer(max(1, len(c) - ABYTES))
        mlen = ctypes.c_ulonglong()
        tag = ctypes.c_ubyte()
        if na.crypto_secretstream_xchacha20poly1305_pull(st, m, ctypes.byref(mlen), ctypes.byref(tag), c,
                                                          ctypes.c_ulonglong(len(c)), aad,
                                                          ctypes.c_ulonglong(len(aad))) != 0:
            raise Fail("mac")
        if (tag.value == TAG_FINAL) != (i == n - 1) or tag.value not in (TAG_FINAL, TAG_MESSAGE):
            raise Fail("tag")
        out += m.raw[:mlen.value]
    buf = (ctypes.c_ubyte * len(out)).from_buffer(out)
    unpadded = ctypes.c_size_t()
    if na.sodium_unpad(ctypes.byref(unpadded), buf, ctypes.c_size_t(len(out)), ctypes.c_size_t(PAD[kind])) != 0:
        raise Fail("pad")
    return bytes(out[:unpadded.value])


def mutate(ct, m):
    ct = bytearray(ct)
    full = CHUNK + ABYTES
    if "flip" in m:
        ct[m["flip"]] ^= 1
    if "truncate" in m:
        del ct[len(ct) - m["truncate"]:]
    if "keep" in m:
        del ct[m["keep"]:]
    if m.get("drop_last_chunk"):
        body = len(ct) - 28
        n = max(1, -(-body // full))
        del ct[28 + (n - 1) * full:]
    if "append_b64" in m:
        ct += b64d(m["append_b64"])
    if "swap_chunks" in m:
        a, b = m["swap_chunks"]
        ca = ct[28 + a * full:28 + (a + 1) * full]
        cb = ct[28 + b * full:28 + (b + 1) * full]
        assert len(ca) == len(cb) == full
        ct[28 + a * full:28 + (a + 1) * full] = cb
        ct[28 + b * full:28 + (b + 1) * full] = ca
    if "set_byte" in m:
        ct[m["set_byte"][0]] = m["set_byte"][1]
    return bytes(ct)


def check_file(path):
    v = json.load(open(path, encoding="utf-8"))
    assert v["format"] == "tsusync-stream-v1", v.get("format")
    n = 0
    s = v["stream"]
    key = b64d(s["data_key"])
    by_name = {}
    for c in s["cases"]:
        expected = pattern(c["plaintext_pattern"]) if "plaintext_pattern" in c else b64d(c["plaintext_b64"])
        ct = b64d(c["ciphertext"])
        got = decrypt(key, c["namespace"], c["kind"], c["id"], ct)
        assert got == expected, c["name"]
        by_name[c["name"]] = c
        n += 1
    for f in s.get("must_fail", []):
        base = by_name[f["base"]]
        m = f["mutation"]
        ctx = {"namespace": base["namespace"], "kind": base["kind"], "id": base["id"], **m.get("context", {})}
        k = b64d(m["key"]) if "key" in m else key
        try:
            decrypt(k, ctx["namespace"], ctx["kind"], ctx["id"], mutate(b64d(base["ciphertext"]), m))
        except Fail:
            n += 1
            continue
        raise AssertionError(f"{f['name']}: lẽ ra phải thất bại")
    kdf = v.get("kdf", {})
    for c in kdf.get("cases", []):
        dk, chk = derive(c["password"], b64d(c["salt"]), c["ops"], c["mem"])
        assert (dk, chk) == (b64d(c["data_key"]), b64d(c["check"])), c["name"]
        n += 1
    for c in kdf.get("reject", []):
        try:
            derive(c["password"], b64d(c["salt"]), c["ops"], c["mem"])
        except Fail as e:
            assert str(e) == c["error"], (c["name"], str(e))
            n += 1
            continue
        raise AssertionError(f"{c['name']}: lẽ ra phải bị từ chối")
    for c in kdf.get("unlock", []):
        p = c["params"]
        assert p["v"] == 1 and p["alg"] == "argon2id13"
        dk, chk = derive(c["password"], b64d(p["salt"]), p["ops"], p["mem"])
        if "error" in c:
            assert chk != b64d(p["check"]), c["name"]
        else:
            assert chk == b64d(p["check"]) and dk == b64d(c["data_key"]), c["name"]
        n += 1
    print(f"{path}: {n} ca khớp libsodium {na.sodium_version_string().decode()}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for p in sys.argv[1:]:
        check_file(p)
