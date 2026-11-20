// Phát vector do CHÍNH thư viện Dart mã hoá/suy khoá, cùng khuôn conformance/vectors-v1.json, để CI kiểm chiều ngược
// lại bằng libsodium độc lập: `dart run tool/emit_vectors.dart > /tmp/dart.json`
// rồi `python3 -I ../../conformance/verify_libsodium.py /tmp/dart.json`.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';
import 'package:tsusync/tsusync.dart';

Uint8List pattern(int n) => Uint8List.fromList([for (var i = 0; i < n; i++) (i * 31 + 7) & 0xff]);

Future<void> main() async {
  final c = await TsuSyncCrypto.init();
  final raw = Uint8List.fromList([for (var i = 0; i < 32; i++) (0x55 + i) & 0xff]);
  final key = SecureKey.fromList(c.sodium, raw);
  final cases = <Map<String, Object>>[];
  for (final (name, kind, id, n) in [
    ('dart-rec-empty', CipherKind.rec, 'r0', 0),
    ('dart-rec-300', CipherKind.rec, 'r1', 300),
    ('dart-file-two-chunks', CipherKind.file, 'f1', 65536),
    ('dart-file-three-chunks', CipherKind.file, 'f2', 2 * 65536 + 100),
  ]) {
    final ct = await c.encrypt(key, CipherContext(namespace: 'tsudev-test', kind: kind, id: id), pattern(n));
    cases.add({
      'name': name,
      'namespace': 'tsudev-test',
      'kind': kind.name,
      'id': id,
      'plaintext_pattern': n,
      'ciphertext': TsuSyncCrypto.b64u(ct),
    });
  }
  final salt = Uint8List.fromList(List.generate(16, (i) => 0xF0 - i));
  const pw = 'Mật khẩu đồng bộ năm 2026';
  final (dk, check) = c.deriveRaw(pw, salt, TsuSyncCrypto.minOps, TsuSyncCrypto.minMem);
  final created = c.createKeys(pw, ops: TsuSyncCrypto.minOps, mem: TsuSyncCrypto.minMem);
  stdout.writeln(
    jsonEncode({
      'format': 'tsusync-stream-v1',
      'stream': {'data_key': TsuSyncCrypto.b64u(raw), 'cases': cases},
      'kdf': {
        'cases': [
          {
            'name': 'dart-kdf',
            'password': pw,
            'salt': TsuSyncCrypto.b64u(salt),
            'ops': TsuSyncCrypto.minOps,
            'mem': TsuSyncCrypto.minMem,
            'data_key': TsuSyncCrypto.b64u(dk.extractBytes()),
            'check': TsuSyncCrypto.b64u(check),
          },
        ],
        'unlock': [
          {
            'name': 'dart-created',
            'params': created.params.toJson(),
            'password': pw,
            'data_key': TsuSyncCrypto.b64u(created.dataKey.extractBytes()),
          },
        ],
      },
    }),
  );
}
