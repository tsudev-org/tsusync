import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:http/http.dart' as http;

import 'crypto.dart';

/// Lấy JWS quyền lợi từ tsudev.com; [forceRefresh] = true khi máy chủ báo JWS cũ (`stale`).
typedef JwsProvider = Future<String> Function(bool forceRefresh);

/// Trả bằng chứng DPoP (RFC 9449) cho một yêu cầu. Nối với `DpopSigner.proof` của `tsudev_ui`:
/// `(method, url, jws) => signer.proof(method, url, accessToken: jws)`.
typedef DpopProof = Future<String> Function(String method, Uri url, String jws);

class SyncHttpException implements Exception {
  const SyncHttpException(this.status, this.code, {this.reason, this.retryAfter});
  final int status;
  final String code;
  final String? reason;

  /// Giây, từ header `Retry-After` (503 `busy`, `entitlements_unavailable`).
  final int? retryAfter;
  @override
  String toString() => 'SyncHttpException: $status $code${reason == null ? '' : ' ($reason)'}';
}

/// Tài khoản không có Pro (`no_pro`) hoặc đã quá 90 ngày sau hết hạn (`grace_expired`). App hiện màn Pro, KHÔNG
/// thử lại (PRODUCT_POLICY 7.4).
class ProRequiredException extends SyncHttpException {
  const ProRequiredException({String? reason}) : super(402, 'pro_required', reason: reason);
}

class PushItem {
  const PushItem({required this.id, this.baseRev, this.deleted = false, this.payload});
  final String id;
  final int? baseRev;
  final bool deleted;
  final String? payload;

  Map<String, Object> toJson() => {
    'id': id,
    'base_rev': ?baseRev,
    if (deleted) 'deleted': true,
    if (!deleted) 'payload': ?payload,
  };
}

class PullItem {
  const PullItem({required this.id, required this.rev, required this.deleted, this.payload});
  final String id;
  final int rev;
  final bool deleted;
  final String? payload;

  static PullItem fromJson(Map<String, Object?> j) => PullItem(
    id: j['id']! as String,
    rev: j['rev']! as int,
    deleted: j['deleted'] == true,
    payload: j['payload'] as String?,
  );
}

class SyncPage<T> {
  const SyncPage(this.items, this.next, this.more);
  final List<T> items;
  final int next;
  final bool more;
}

/// Máy khách HTTP của TsuDEV Sync (ADR-0001 mục 3, ADR-0002 mục 3.2). Chỉ chuyển bản mã; [SyncSession] ghép mã hoá.
class SyncClient {
  SyncClient({
    required Uri baseUrl,
    required this.getJws,
    this.installationId,
    this.dpop,
    http.Client? httpClient,
  }) : _base = baseUrl.toString().replaceFirst(RegExp(r'/+$'), ''),
       _http = httpClient ?? http.Client() {
    if (installationId != null && !_installation.hasMatch(installationId!)) {
      throw ArgumentError.value(installationId, 'installationId', 'phải đúng 22 ký tự base64url');
    }
  }

  final String _base;
  final http.Client _http;
  final JwsProvider getJws;
  final String? installationId;
  final DpopProof? dpop;

  static final _id = RegExp(r'^[A-Za-z0-9._~:-]{1,128}$');
  static final _installation = RegExp(r'^[A-Za-z0-9_-]{22}$');

  static void _assertId(String id) {
    if (!_id.hasMatch(id)) {
      throw ArgumentError.value(id, 'id', 'phải 1-128 ký tự [A-Za-z0-9._~:-] và không chứa bản rõ');
    }
  }

  Future<http.Response> _send(String method, String path, {List<int>? body, Map<String, String>? headers}) async {
    final url = Uri.parse('$_base$path');
    for (var attempt = 0; ; attempt++) {
      final jws = await getJws(attempt > 0);
      final req = http.Request(method, url);
      req.headers.addAll(headers ?? const {});
      if (installationId != null) req.headers['X-Tsu-Installation'] = installationId!;
      if (dpop != null) {
        // `htu` không có query (RFC 9449 mục 4.2).
        req.headers['DPoP'] = await dpop!(method, Uri.parse('$_base${path.split('?').first}'), jws);
        req.headers['Authorization'] = 'DPoP $jws';
      } else {
        req.headers['Authorization'] = 'Bearer $jws';
      }
      if (body != null) req.bodyBytes = body;
      final res = await http.Response.fromStream(await _http.send(req));
      if (res.statusCode >= 200 && res.statusCode < 300) return res;
      var code = 'http_error';
      String? reason;
      try {
        final j = jsonDecode(res.body);
        if (j is Map) {
          if (j['error'] is String) code = j['error'] as String;
          if (j['reason'] is String) reason = j['reason'] as String;
        }
      } on FormatException {
        // thân không phải JSON
      }
      if (res.statusCode == 401 && reason == 'stale' && attempt == 0) continue;
      if (res.statusCode == 402) throw ProRequiredException(reason: reason);
      final ra = int.tryParse(res.headers['retry-after'] ?? '');
      throw SyncHttpException(res.statusCode, code, reason: reason, retryAfter: ra != null && ra > 0 ? ra : null);
    }
  }

  static Map<String, Object?> _json(http.Response r) => jsonDecode(utf8.decode(r.bodyBytes)) as Map<String, Object?>;

  /// Đẩy 1-100 mục. Kết quả từng mục giữ nguyên dạng JSON của máy chủ (`applied`/`unchanged`/`conflict`/`rejected`).
  Future<({List<Map<String, Object?>> results, int rev})> pushRecords(List<PushItem> items) async {
    if (items.isEmpty || items.length > 100) throw ArgumentError.value(items.length, 'items', 'mỗi lô 1-100 mục');
    for (final it in items) {
      _assertId(it.id);
    }
    final j = _json(
      await _send(
        'POST',
        '/v1/records',
        body: utf8.encode(jsonEncode({'items': items.map((e) => e.toJson()).toList()})),
        headers: {'Content-Type': 'application/json'},
      ),
    );
    return (results: (j['results']! as List).cast<Map<String, Object?>>(), rev: j['rev']! as int);
  }

  Future<SyncPage<PullItem>> pullRecords({int since = 0, int limit = 500}) async {
    final j = _json(await _send('GET', '/v1/records?since=$since&limit=$limit'));
    return SyncPage(
      (j['items']! as List).cast<Map<String, Object?>>().map(PullItem.fromJson).toList(),
      j['next']! as int,
      j['more'] == true,
    );
  }

  Future<SyncPage<Map<String, Object?>>> listFiles({int since = 0, int limit = 200}) async {
    final j = _json(await _send('GET', '/v1/files?since=$since&limit=$limit'));
    return SyncPage((j['items']! as List).cast<Map<String, Object?>>(), j['next']! as int, j['more'] == true);
  }

  Future<Map<String, Object?>> putFile(String id, Uint8List ciphertext) async {
    _assertId(id);
    if (ciphertext.length > 64 * 1024 * 1024) {
      throw ArgumentError('Tệp > 64 MiB: hãy chia khối ở tầng ứng dụng.');
    }
    return _json(
      await _send(
        'PUT',
        '/v1/files/$id',
        body: ciphertext,
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Tsu-Digest': TsuSyncCrypto.b64u(sha256.convert(ciphertext).bytes),
        },
      ),
    );
  }

  Future<Uint8List> getFile(String id) async {
    _assertId(id);
    return (await _send('GET', '/v1/files/$id')).bodyBytes;
  }

  Future<Map<String, Object?>> deleteFile(String id) async {
    _assertId(id);
    return _json(await _send('DELETE', '/v1/files/$id'));
  }

  Future<Map<String, Object?>> account() async => _json(await _send('GET', '/v1/account'));

  void close() => _http.close();
}

/// Ghép [SyncClient] với khoá dữ liệu: mã hoá với ngữ cảnh [namespace] (= `client_id` tại tsudev.com) + loại + id.
class SyncSession {
  SyncSession(this.client, this.crypto, this.keys, this.namespace);
  final SyncClient client;
  final TsuSyncCrypto crypto;
  final SyncKeys keys;
  final String namespace;

  Future<String> sealRecord(String id, Uint8List plaintext) async {
    final ct = await crypto.encrypt(
      keys.dataKey,
      CipherContext(namespace: namespace, kind: CipherKind.rec, id: id),
      plaintext,
    );
    if (ct.length > 64 * 1024) throw ArgumentError('Bản ghi sau mã hoá vượt 64 KiB: hãy lưu dưới dạng tệp.');
    return TsuSyncCrypto.b64u(ct);
  }

  Future<Uint8List?> openRecord(PullItem item) async {
    if (item.deleted || item.payload == null) return null;
    return crypto.decrypt(
      keys.dataKey,
      CipherContext(namespace: namespace, kind: CipherKind.rec, id: item.id),
      TsuSyncCrypto.fromB64u(item.payload!),
    );
  }

  Future<Map<String, Object?>> putPlainFile(String id, Uint8List data) async => client.putFile(
    id,
    await crypto.encrypt(keys.dataKey, CipherContext(namespace: namespace, kind: CipherKind.file, id: id), data),
  );

  Future<Uint8List> getPlainFile(String id) async => crypto.decrypt(
    keys.dataKey,
    CipherContext(namespace: namespace, kind: CipherKind.file, id: id),
    await client.getFile(id),
  );
}
