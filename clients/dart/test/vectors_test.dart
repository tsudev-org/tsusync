import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';
import 'package:test/test.dart';
import 'package:tsusync/tsusync.dart';

Uint8List pattern(int n) => Uint8List.fromList([for (var i = 0; i < n; i++) (i * 31 + 7) & 0xff]);

const full = TsuSyncCrypto.chunkBytes + TsuSyncCrypto.aBytes;
const head = 28;

/// Áp đột biến của `must_fail` - CÙNG ngữ nghĩa với conformance/verify_libsodium.py và test TypeScript.
Uint8List mutate(Uint8List src, Map<String, Object?> m) {
  var ct = Uint8List.fromList(src);
  final flip = m['flip'] as int?;
  if (flip != null) ct[flip < 0 ? ct.length + flip : flip] ^= 1;
  final truncate = m['truncate'] as int?;
  if (truncate != null) ct = Uint8List.sublistView(ct, 0, ct.length - truncate);
  final keep = m['keep'] as int?;
  if (keep != null) ct = Uint8List.sublistView(ct, 0, keep);
  if (m['drop_last_chunk'] == true) {
    final n = ((ct.length - head) + full - 1) ~/ full;
    ct = Uint8List.sublistView(ct, 0, head + (n < 1 ? 0 : n - 1) * full);
  }
  final append = m['append_b64'] as String?;
  if (append != null) ct = Uint8List.fromList([...ct, ...TsuSyncCrypto.fromB64u(append)]);
  final swap = (m['swap_chunks'] as List?)?.cast<int>();
  if (swap != null) {
    final a = swap[0], b = swap[1];
    final ca = Uint8List.fromList(ct.sublist(head + a * full, head + (a + 1) * full));
    final cb = Uint8List.fromList(ct.sublist(head + b * full, head + (b + 1) * full));
    ct
      ..setAll(head + a * full, cb)
      ..setAll(head + b * full, ca);
  }
  final setByte = (m['set_byte'] as List?)?.cast<int>();
  if (setByte != null) ct[setByte[0]] = setByte[1];
  return Uint8List.fromList(ct);
}

CipherKind kindOf(String s) => CipherKind.values.byName(s);

void main() {
  late TsuSyncCrypto c;
  final v = jsonDecode(File('../../conformance/vectors-v1.json').readAsStringSync()) as Map<String, Object?>;
  final stream = v['stream']! as Map<String, Object?>;
  final cases = (stream['cases']! as List).cast<Map<String, Object?>>();
  final kdf = v['kdf']! as Map<String, Object?>;
  final dataKey = TsuSyncCrypto.fromB64u(stream['data_key']! as String);

  setUpAll(() async => c = await TsuSyncCrypto.init());

  test('đúng định dạng', () => expect(v['format'], 'tsusync-stream-v1'));

  group('mở được', () {
    for (final cs in cases) {
      test(cs['name'], () async {
        final expected = cs['plaintext_pattern'] != null
            ? pattern(cs['plaintext_pattern']! as int)
            : TsuSyncCrypto.fromB64u(cs['plaintext_b64']! as String);
        final key = SecureKey.fromList(c.sodium, dataKey);
        final ctx = CipherContext(
          namespace: cs['namespace']! as String,
          kind: kindOf(cs['kind']! as String),
          id: cs['id']! as String,
        );
        final got = await c.decrypt(key, ctx, TsuSyncCrypto.fromB64u(cs['ciphertext']! as String));
        expect(TsuSyncCrypto.b64u(got), TsuSyncCrypto.b64u(expected));
      });
    }
  });

  group('từ chối', () {
    for (final f in (stream['must_fail']! as List).cast<Map<String, Object?>>()) {
      test(f['name'], () async {
        final base = cases.firstWhere((x) => x['name'] == f['base']);
        final m = f['mutation']! as Map<String, Object?>;
        final over = (m['context'] as Map?)?.cast<String, String>() ?? const {};
        final ctx = CipherContext(
          namespace: over['namespace'] ?? base['namespace']! as String,
          kind: kindOf(over['kind'] ?? base['kind']! as String),
          id: over['id'] ?? base['id']! as String,
        );
        final key = SecureKey.fromList(
          c.sodium,
          m['key'] != null ? TsuSyncCrypto.fromB64u(m['key']! as String) : dataKey,
        );
        final ct = mutate(TsuSyncCrypto.fromB64u(base['ciphertext']! as String), m);
        await expectLater(c.decrypt(key, ctx, ct), throwsA(isA<TsuSyncCryptoException>()));
      });
    }
  });

  group('suy khoá', () {
    for (final k in (kdf['cases']! as List).cast<Map<String, Object?>>()) {
      test(k['name'], () {
        final (key, check) = c.deriveRaw(
          k['password']! as String,
          TsuSyncCrypto.fromB64u(k['salt']! as String),
          k['ops']! as int,
          k['mem']! as int,
        );
        expect(TsuSyncCrypto.b64u(key.extractBytes()), k['data_key']);
        expect(TsuSyncCrypto.b64u(check), k['check']);
      });
    }
    for (final k in (kdf['reject']! as List).cast<Map<String, Object?>>()) {
      test('từ chối ${k['name']}', () {
        expect(
          () => c.deriveRaw(
            k['password']! as String,
            TsuSyncCrypto.fromB64u(k['salt']! as String),
            k['ops']! as int,
            k['mem']! as int,
          ),
          throwsA(k['error'] == 'weak_password' ? isA<WeakPasswordException>() : isA<TsuSyncCryptoException>()),
        );
      });
    }
    for (final k in (kdf['unlock']! as List).cast<Map<String, Object?>>()) {
      test(k['name'], () {
        if (k['error'] != null) {
          expect(() => c.unlockKeys(k['password']! as String, k['params']), throwsA(isA<WrongPasswordException>()));
        } else {
          final keys = c.unlockKeys(k['password']! as String, k['params']);
          expect(TsuSyncCrypto.b64u(keys.dataKey.extractBytes()), k['data_key']);
          expect(keys.params.toJson(), k['params']);
        }
      });
    }
  });

  group('khứ hồi', () {
    for (final (kind, n) in [
      (CipherKind.rec, 0),
      (CipherKind.rec, 1),
      (CipherKind.file, TsuSyncCrypto.chunkBytes - 1),
      (CipherKind.file, TsuSyncCrypto.chunkBytes),
      (CipherKind.file, 3 * TsuSyncCrypto.chunkBytes + 7),
    ]) {
      test('${kind.name} $n byte', () async {
        final key = SecureKey.fromList(c.sodium, dataKey);
        final ctx = CipherContext(namespace: 'tsudev-test', kind: kind, id: 'x1');
        final ct = await c.encrypt(key, ctx, pattern(n));
        expect(TsuSyncCrypto.b64u(await c.decrypt(key, ctx, ct)), TsuSyncCrypto.b64u(pattern(n)));
        expect(TsuSyncCrypto.b64u(await c.encrypt(key, ctx, pattern(n))), isNot(TsuSyncCrypto.b64u(ct)));
      });
    }

    test('ngữ cảnh sai định dạng bị từ chối', () async {
      final key = SecureKey.fromList(c.sodium, dataKey);
      await expectLater(
        c.encrypt(key, const CipherContext(namespace: 'ns', kind: CipherKind.rec, id: 'tên tệp.pdf'), pattern(1)),
        throwsA(isA<TsuSyncCryptoException>()),
      );
    });

    test('createKeys + unlockKeys khứ hồi qua JSON', () {
      const pw = 'mật khẩu đủ dài 2026';
      final k = c.createKeys(pw, ops: TsuSyncCrypto.minOps, mem: TsuSyncCrypto.minMem);
      final json = jsonDecode(jsonEncode(k.params.toJson()));
      final u = c.unlockKeys(pw, json);
      expect(u.dataKey.extractBytes(), k.dataKey.extractBytes());
      expect(
        () => c.unlockKeys(pw, {...(json as Map<String, Object?>), 'ops': 1}),
        throwsA(isA<TsuSyncCryptoException>()),
      );
    });
  });
}
