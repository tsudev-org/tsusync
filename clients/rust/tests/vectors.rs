//! Vector đối chiếu `conformance/vectors-v1.json` - CÙNG khuôn với clients/dart/test/vectors_test.dart, test TypeScript
//! và conformance/verify_libsodium.py.

use serde_json::{Value, json};
use tsusync::*;

const FULL: usize = CHUNK_BYTES + ABYTES;
const HEAD: usize = PREFIX_BYTES + HEADER_BYTES;

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
}

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/vectors-v1.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("đọc vector")).expect("JSON vector")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("thiếu {k}"))
}

fn key32(b64: &str) -> [u8; 32] {
    from_b64u(b64).unwrap().try_into().expect("khoá 32 B")
}

/// Áp đột biến của `must_fail` - CÙNG ngữ nghĩa với verify_libsodium.py và test Dart/TypeScript.
fn mutate(src: &[u8], m: &Value) -> Vec<u8> {
    let mut ct = src.to_vec();
    if let Some(flip) = m["flip"].as_i64() {
        let i = if flip < 0 { ct.len() - flip.unsigned_abs() as usize } else { flip as usize };
        ct[i] ^= 1;
    }
    if let Some(t) = m["truncate"].as_u64() {
        ct.truncate(ct.len() - t as usize);
    }
    if let Some(k) = m["keep"].as_u64() {
        ct.truncate(k as usize);
    }
    if m["drop_last_chunk"] == json!(true) {
        let n = (ct.len() - HEAD).div_ceil(FULL).max(1);
        ct.truncate(HEAD + (n - 1) * FULL);
    }
    if let Some(a) = m["append_b64"].as_str() {
        ct.extend(from_b64u(a).unwrap());
    }
    if let Some(sw) = m["swap_chunks"].as_array() {
        let (a, b) = (sw[0].as_u64().unwrap() as usize, sw[1].as_u64().unwrap() as usize);
        let ca = ct[HEAD + a * FULL..HEAD + (a + 1) * FULL].to_vec();
        let cb = ct[HEAD + b * FULL..HEAD + (b + 1) * FULL].to_vec();
        ct[HEAD + a * FULL..HEAD + (a + 1) * FULL].copy_from_slice(&cb);
        ct[HEAD + b * FULL..HEAD + (b + 1) * FULL].copy_from_slice(&ca);
    }
    if let Some(sb) = m["set_byte"].as_array() {
        ct[sb[0].as_u64().unwrap() as usize] = sb[1].as_u64().unwrap() as u8;
    }
    ct
}

fn ctx_of(c: &Value) -> CipherContext {
    CipherContext::new(s(c, "namespace"), Kind::from_name(s(c, "kind")).unwrap(), s(c, "id"))
}

#[test]
fn dung_dinh_dang() {
    assert_eq!(vectors()["format"], "tsusync-stream-v1");
}

#[test]
fn mo_duoc() {
    let v = vectors();
    let key = key32(s(&v["stream"], "data_key"));
    let cases = v["stream"]["cases"].as_array().unwrap();
    assert!(cases.len() >= 7);
    for c in cases {
        let expected = match c["plaintext_pattern"].as_u64() {
            Some(n) => pattern(n as usize),
            None => from_b64u(s(c, "plaintext_b64")).unwrap(),
        };
        let got = decrypt(&key, &ctx_of(c), &from_b64u(s(c, "ciphertext")).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", s(c, "name")));
        assert_eq!(got, expected, "{}", s(c, "name"));
    }
}

#[test]
fn tu_choi() {
    let v = vectors();
    let key = key32(s(&v["stream"], "data_key"));
    let cases = v["stream"]["cases"].as_array().unwrap();
    let fails = v["stream"]["must_fail"].as_array().unwrap();
    assert!(fails.len() >= 16);
    for f in fails {
        let base = cases.iter().find(|c| c["name"] == f["base"]).expect("ca gốc");
        let m = &f["mutation"];
        let over = |k: &str| m["context"][k].as_str().unwrap_or(s(base, k)).to_owned();
        let ctx = CipherContext::new(over("namespace"), Kind::from_name(&over("kind")).unwrap(), over("id"));
        let k = m["key"].as_str().map(key32).unwrap_or(key);
        let r = decrypt(&k, &ctx, &mutate(&from_b64u(s(base, "ciphertext")).unwrap(), m));
        assert!(matches!(r, Err(Error::Crypto(_))), "{}: lẽ ra phải thất bại", s(f, "name"));
    }
}

#[test]
fn suy_khoa() {
    let v = vectors();
    let kdf = &v["kdf"];
    for k in kdf["cases"].as_array().unwrap() {
        let d = derive_raw(
            s(k, "password"),
            &from_b64u(s(k, "salt")).unwrap(),
            k["ops"].as_u64().unwrap(),
            k["mem"].as_u64().unwrap(),
        )
        .unwrap();
        assert_eq!(b64u(&d.data_key[..]), s(k, "data_key"), "{}", s(k, "name"));
        assert_eq!(b64u(&d.check), s(k, "check"), "{}", s(k, "name"));
    }
    for k in kdf["reject"].as_array().unwrap() {
        let r = derive_raw(
            s(k, "password"),
            &from_b64u(s(k, "salt")).unwrap(),
            k["ops"].as_u64().unwrap(),
            k["mem"].as_u64().unwrap(),
        );
        match s(k, "error") {
            "weak_password" => assert!(matches!(r, Err(Error::WeakPassword)), "{}", s(k, "name")),
            _ => assert!(matches!(r, Err(Error::Crypto(_))), "{}", s(k, "name")),
        }
    }
    for k in kdf["unlock"].as_array().unwrap() {
        let r = unlock_keys(s(k, "password"), &k["params"]);
        if k.get("error").is_some() {
            assert!(matches!(r, Err(Error::WrongPassword)), "{}", s(k, "name"));
        } else {
            let keys = r.unwrap();
            assert_eq!(b64u(&keys.data_key[..]), s(k, "data_key"));
            assert_eq!(keys.params.to_json(), k["params"]);
        }
    }
}

#[test]
fn khu_hoi() {
    let key = key32(s(&vectors()["stream"], "data_key"));
    for (kind, n) in [
        (Kind::Rec, 0),
        (Kind::Rec, 1),
        (Kind::File, CHUNK_BYTES - 1),
        (Kind::File, CHUNK_BYTES),
        (Kind::File, 3 * CHUNK_BYTES + 7),
    ] {
        let ctx = CipherContext::new("tsudev-test", kind, "x1");
        let ct = encrypt(&key, &ctx, &pattern(n)).unwrap();
        assert_eq!(decrypt(&key, &ctx, &ct).unwrap(), pattern(n), "{kind:?} {n}");
        assert_ne!(encrypt(&key, &ctx, &pattern(n)).unwrap(), ct);
    }
}

#[test]
fn ngu_canh_sai_dinh_dang_bi_tu_choi() {
    let key = [7u8; 32];
    for (ns, id) in [("ns", "tên tệp.pdf"), ("", "a"), ("ns", &"a".repeat(129)), ("a|b", "c")] {
        let r = encrypt(&key, &CipherContext::new(ns, Kind::Rec, id), &pattern(1));
        assert!(matches!(r, Err(Error::Crypto(_))), "{ns} {id}");
    }
    assert!(encrypt(&key, &CipherContext::new("ns", Kind::Rec, "a".repeat(128)), b"x").is_ok());
}

#[test]
fn tao_khoa_va_mo_khoa_khu_hoi_qua_json() {
    let pw = "mật khẩu đủ dài 2026";
    let k = create_keys(pw, Some(KDF_MIN)).unwrap();
    let json: Value = serde_json::from_str(&k.params.to_json().to_string()).unwrap();
    let u = unlock_keys(pw, &json).unwrap();
    assert_eq!(*u.data_key, *k.data_key);
    let mut weak = json.clone();
    weak["ops"] = json!(1);
    assert!(matches!(unlock_keys(pw, &weak), Err(Error::Crypto(_))));
    let mut alg = json.clone();
    alg["alg"] = json!("argon2i13");
    assert!(matches!(unlock_keys(pw, &alg), Err(Error::Crypto(_))));
    assert!(matches!(unlock_keys("mật khẩu sai rồi 2026", &json), Err(Error::WrongPassword)));
}

#[test]
fn base64url_nghiem() {
    for n in 0..8 {
        let b = pattern(n);
        assert_eq!(from_b64u(&b64u(&b)).unwrap(), b);
    }
    assert_eq!(b64u(b"\xfb\xff"), "-_8");
    for bad in ["A", "AB=", "a+b", "AB/C", "-_9"] {
        assert!(from_b64u(bad).is_err(), "{bad}");
    }
}
