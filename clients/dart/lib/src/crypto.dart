import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';
import 'package:unorm_dart/unorm_dart.dart' as unorm;

/// Giải mã/mở khoá thất bại. Thông điệp cố ý chung - không nói khoá sai hay dữ liệu bị sửa.
final class TsuSyncCryptoException implements Exception {
  const TsuSyncCryptoException([this.message = 'Không mở được dữ liệu mã hoá.']);
  final String message;
  @override
  String toString() => 'TsuSyncCryptoException: $message';
}

final class WeakPasswordException implements Exception {
  const WeakPasswordException();
  @override
  String toString() => 'WeakPasswordException: mật khẩu đồng bộ cần ít nhất ${TsuSyncCrypto.minPasswordLength} ký tự';
}

final class WrongPasswordException implements Exception {
  const WrongPasswordException();
  @override
  String toString() => 'WrongPasswordException: mật khẩu đồng bộ không đúng';
}

/// Loại bản mã - byte thứ tư của tiền tố và một phần của ngữ cảnh. Khối đệm: bản ghi 256 B, tệp 4096 B.
enum CipherKind {
  rec(1, 256),
  file(2, 4096);

  const CipherKind(this.byte, this.padBlock);
  final int byte;
  final int padBlock;
}

/// Ngữ cảnh gắn vào AAD: bản mã chỉ mở được đúng sản phẩm + loại + định danh đã tạo ra nó.
final class CipherContext {
  const CipherContext({required this.namespace, required this.kind, required this.id});
  final String namespace;
  final CipherKind kind;
  final String id;
}

/// Tham số KDF lưu kèm dữ liệu (không bí mật). Khuôn JSON giống hệt `KdfParams` của `@tsudev/sync`.
final class KdfParams {
  const KdfParams({required this.salt, required this.ops, required this.mem, required this.check});
  final String salt;
  final int ops;
  final int mem;
  final String check;

  Map<String, Object> toJson() => {'v': 1, 'alg': 'argon2id13', 'salt': salt, 'ops': ops, 'mem': mem, 'check': check};

  static KdfParams fromJson(Object? raw) {
    if (raw is! Map || raw['v'] != 1 || raw['alg'] != 'argon2id13') {
      throw const TsuSyncCryptoException('Tham số KDF không hỗ trợ.');
    }
    final salt = raw['salt'], check = raw['check'], ops = raw['ops'], mem = raw['mem'];
    if (salt is! String || check is! String || ops is! int || mem is! int) {
      throw const TsuSyncCryptoException('Tham số KDF không hợp lệ.');
    }
    TsuSyncCrypto.checkKdfRange(ops, mem);
    return KdfParams(salt: salt, ops: ops, mem: mem, check: check);
  }
}

/// Khoá dữ liệu 32 B trong bộ nhớ khoá của libsodium. Gọi [dispose] khi khoá phiên/đăng xuất.
final class SyncKeys {
  SyncKeys(this.dataKey, this.params);
  final SecureKey dataKey;
  final KdfParams params;
  void dispose() => dataKey.dispose();
}

/// Mã hoá đầu cuối định dạng `TS 01` (ADR-0003) - CÙNG hợp đồng với `@tsudev/sync`, đối chiếu bằng
/// `conformance/vectors-v1.json`.
///
/// - Khoá gốc = Argon2id13(NFKC(mật khẩu), muối 16 B, ≥ 3 lượt / 64 MiB) - thông số qulythuchi ADR-0007.
/// - Khoá dữ liệu = crypto_kdf(gốc, 1, "TSUSYNC1"); mã kiểm = crypto_kdf(gốc, 2, "TSUSYNC1", 16 B).
/// - Bản mã = 'T' 'S' 01 <loại> ‖ header 24 B ‖ khối secretstream (bản rõ sodium_pad, khối 64 KiB, khối cuối
///   TAG_FINAL); AAD mỗi khối = 4 byte đầu ‖ UTF-8("tsusync|v1|<ns>|<loại>|<id>").
final class TsuSyncCrypto {
  TsuSyncCrypto(this.sodium);

  final SodiumSumo sodium;

  static Future<TsuSyncCrypto> init() async => TsuSyncCrypto(await SodiumSumoInit.init());

  static const formatVersion = 1;
  static const chunkBytes = 64 * 1024;
  static const headerBytes = 24;
  static const aBytes = 17;
  static const prefixBytes = 4;
  static const kdfContext = 'TSUSYNC1';
  static const saltBytes = 16;
  static const minPasswordLength = 10;
  static const defaultOps = 3, defaultMem = 64 * 1024 * 1024;
  static const minOps = 2, minMem = 19 * 1024 * 1024;
  static const maxOps = 16, maxMem = 1024 * 1024 * 1024;

  static final _safe = RegExp(r'^[A-Za-z0-9._~:-]{1,128}$');
  static final _b64u = RegExp(r'^[A-Za-z0-9_-]*$');

  static String b64u(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

  static Uint8List fromB64u(String s) {
    if (!_b64u.hasMatch(s) || s.length % 4 == 1) throw const TsuSyncCryptoException('Chuỗi base64url không hợp lệ.');
    return base64Url.decode(base64Url.normalize(s));
  }

  /// NFKC rồi đếm theo code point (không theo đơn vị UTF-16) - giống `[...s].length` của TypeScript.
  static String normalizePassword(String password) {
    final n = unorm.nfkc(password);
    if (n.runes.length < minPasswordLength) throw const WeakPasswordException();
    return n;
  }

  static void checkKdfRange(int ops, int mem) {
    if (ops < minOps || mem < minMem) throw const TsuSyncCryptoException('Tham số KDF yếu hơn mức tối thiểu.');
    if (ops > maxOps || mem > maxMem) throw const TsuSyncCryptoException('Tham số KDF vượt trần.');
  }

  /// Suy khoá - hàm thuần, dùng cho tạo mới, mở khoá và vector. Trả (khoá dữ liệu, mã kiểm 16 B).
  (SecureKey, Uint8List) deriveRaw(String password, Uint8List salt, int ops, int mem) {
    checkKdfRange(ops, mem);
    if (salt.length != saltBytes) throw const TsuSyncCryptoException('Muối KDF phải dài 16 byte.');
    final pw = utf8.encode(normalizePassword(password));
    final root = sodium.crypto.pwhash.callRaw(
      outLen: 32,
      password: Int8List.view(pw.buffer, pw.offsetInBytes, pw.length),
      salt: salt,
      opsLimit: ops,
      memLimit: mem,
      alg: CryptoPwhashAlgorithm.argon2id13,
    );
    try {
      final dataKey = sodium.crypto.kdf.deriveFromKey(
        masterKey: root,
        context: kdfContext,
        subkeyId: BigInt.one,
        subkeyLen: 32,
      );
      final checkKey = sodium.crypto.kdf.deriveFromKey(
        masterKey: root,
        context: kdfContext,
        subkeyId: BigInt.two,
        subkeyLen: 16,
      );
      final check = checkKey.extractBytes();
      checkKey.dispose();
      return (dataKey, check);
    } finally {
      root.dispose();
      pw.fillRange(0, pw.length, 0);
    }
  }

  /// Tạo khoá mới (lần đầu bật đồng bộ).
  SyncKeys createKeys(String password, {int ops = defaultOps, int mem = defaultMem}) {
    final salt = sodium.randombytes.buf(saltBytes);
    final (dataKey, check) = deriveRaw(password, salt, ops, mem);
    return SyncKeys(dataKey, KdfParams(salt: b64u(salt), ops: ops, mem: mem, check: b64u(check)));
  }

  /// Mở khoá bằng tham số đã lưu (Map JSON hoặc [KdfParams]). Sai mật khẩu ⇒ [WrongPasswordException].
  SyncKeys unlockKeys(String password, Object? params) {
    final p = params is KdfParams ? params : KdfParams.fromJson(params);
    final (dataKey, check) = deriveRaw(password, fromB64u(p.salt), p.ops, p.mem);
    final expected = fromB64u(p.check);
    var diff = expected.length ^ check.length;
    for (var i = 0; i < check.length && i < expected.length; i++) {
      diff |= expected[i] ^ check[i];
    }
    if (diff != 0) {
      dataKey.dispose();
      throw const WrongPasswordException();
    }
    return SyncKeys(dataKey, p);
  }

  static Uint8List _prefix(CipherKind kind) => Uint8List.fromList([0x54, 0x53, formatVersion, kind.byte]);

  static Uint8List _aad(CipherContext ctx) {
    if (!_safe.hasMatch(ctx.namespace) || !_safe.hasMatch(ctx.id)) {
      throw const TsuSyncCryptoException('Ngữ cảnh mã hoá không hợp lệ.');
    }
    return Uint8List.fromList([
      ..._prefix(ctx.kind),
      ...utf8.encode('tsusync|v1|${ctx.namespace}|${ctx.kind.name}|${ctx.id}'),
    ]);
  }

  Future<Uint8List> encrypt(SecureKey dataKey, CipherContext ctx, Uint8List plaintext) async {
    final ad = _aad(ctx);
    final padded = sodium.pad(plaintext, ctx.kind.padBlock);
    final messages = <SecretStreamPlainMessage>[];
    for (var off = 0; ; off += chunkBytes) {
      final last = off + chunkBytes >= padded.length;
      final end = last ? padded.length : off + chunkBytes;
      messages.add(
        SecretStreamPlainMessage(
          Uint8List.sublistView(padded, off, end),
          additionalData: ad,
          tag: last ? SecretStreamMessageTag.finalPush : SecretStreamMessageTag.message,
        ),
      );
      if (last) break;
    }
    final out = await sodium.crypto.secretStream
        .pushEx(messageStream: Stream.fromIterable(messages), key: dataKey)
        .toList();
    // Sự kiện đầu là header secretstream, sau đó mỗi khối một sự kiện.
    if (out.length != messages.length + 1 || out.first.message.length != headerBytes) {
      throw StateError('secretstream push trả số sự kiện bất thường');
    }
    final b = BytesBuilder(copy: false)..add(_prefix(ctx.kind));
    for (final m in out) {
      b.add(m.message);
    }
    return b.takeBytes();
  }

  Future<Uint8List> decrypt(SecureKey dataKey, CipherContext ctx, Uint8List ciphertext) async {
    final ad = _aad(ctx);
    const head = prefixBytes + headerBytes;
    if (ciphertext.length < head + aBytes) throw const TsuSyncCryptoException();
    final expected = _prefix(ctx.kind);
    for (var i = 0; i < prefixBytes; i++) {
      if (ciphertext[i] != expected[i]) throw const TsuSyncCryptoException();
    }
    const full = chunkBytes + aBytes;
    final bodyLen = ciphertext.length - head;
    final n = bodyLen == 0 ? 1 : (bodyLen + full - 1) ~/ full;
    if (bodyLen - (n - 1) * full < aBytes) throw const TsuSyncCryptoException();
    final input = <SecretStreamCipherMessage>[
      SecretStreamCipherMessage(Uint8List.sublistView(ciphertext, prefixBytes, head)),
      for (var i = 0; i < n; i++)
        SecretStreamCipherMessage(
          Uint8List.sublistView(ciphertext, head + i * full, i == n - 1 ? ciphertext.length : head + (i + 1) * full),
          additionalData: ad,
        ),
    ];
    final List<SecretStreamPlainMessage> plain;
    try {
      plain = await sodium.crypto.secretStream
          .pullEx(cipherStream: Stream.fromIterable(input), key: dataKey)
          .toList();
    } on Object {
      // Sai MAC, khối sau TAG_FINAL (StateError được chuyển thành sự kiện lỗi), thiếu khối cuối...
      throw const TsuSyncCryptoException();
    }
    if (plain.length != n) throw const TsuSyncCryptoException();
    final b = BytesBuilder(copy: false);
    for (var i = 0; i < n; i++) {
      final isFinal = plain[i].tag == SecretStreamMessageTag.finalPush;
      // TAG_FINAL đúng ở khối cuối và CHỈ ở đó: chống cắt cụt và chống nối thêm.
      if (isFinal != (i == n - 1) || (!isFinal && plain[i].tag != SecretStreamMessageTag.message)) {
        throw const TsuSyncCryptoException();
      }
      b.add(plain[i].message);
    }
    try {
      return sodium.unpad(b.takeBytes(), ctx.kind.padBlock);
    } on Object {
      throw const TsuSyncCryptoException();
    }
  }
}
