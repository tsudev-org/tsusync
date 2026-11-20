//! Phát vector do CHÍNH thư viện Rust mã hoá/suy khoá, cùng khuôn conformance/vectors-v1.json, để CI kiểm chiều ngược
//! lại bằng libsodium độc lập: `cargo run --example emit_vectors > /tmp/rust.json`
//! rồi `python3 -I ../../conformance/verify_libsodium.py /tmp/rust.json`.

use serde_json::json;
use tsusync::*;

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
}

fn main() -> Result<()> {
    let raw: [u8; 32] = std::array::from_fn(|i| (0x55 + i) as u8);
    let mut cases = Vec::new();
    for (name, kind, id, n) in [
        ("rust-rec-empty", Kind::Rec, "r0", 0),
        ("rust-rec-300", Kind::Rec, "r1", 300),
        ("rust-file-two-chunks", Kind::File, "f1", 65536),
        ("rust-file-three-chunks", Kind::File, "f2", 2 * 65536 + 100),
    ] {
        let ct = encrypt(&raw, &CipherContext::new("tsudev-test", kind, id), &pattern(n))?;
        cases.push(json!({
            "name": name, "namespace": "tsudev-test", "kind": kind.name(), "id": id,
            "plaintext_pattern": n, "ciphertext": b64u(&ct),
        }));
    }
    let salt: [u8; 16] = std::array::from_fn(|i| 0xF0 - i as u8);
    let pw = "Mật khẩu đồng bộ năm 2026";
    let d = derive_raw(pw, &salt, KDF_MIN.ops, KDF_MIN.mem)?;
    let created = create_keys(pw, Some(KDF_MIN))?;
    let out = json!({
        "format": "tsusync-stream-v1",
        "stream": { "data_key": b64u(&raw), "cases": cases },
        "kdf": {
            "cases": [{
                "name": "rust-kdf", "password": pw, "salt": b64u(&salt),
                "ops": KDF_MIN.ops, "mem": KDF_MIN.mem,
                "data_key": b64u(&d.data_key[..]), "check": b64u(&d.check),
            }],
            "unlock": [{
                "name": "rust-created", "params": created.params.to_json(), "password": pw,
                "data_key": b64u(&created.data_key[..]),
            }],
        },
    });
    println!("{out}");
    Ok(())
}
