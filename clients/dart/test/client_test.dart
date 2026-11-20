import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'package:tsusync/tsusync.dart';

http.Response jsonRes(int status, Object body, [Map<String, String> headers = const {}]) =>
    http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json', ...headers});

void main() {
  late TsuSyncCrypto c;
  setUpAll(() async => c = await TsuSyncCrypto.init());

  test('401 stale ⇒ lấy JWS mới rồi thử lại ĐÚNG một lần', () async {
    final auth = <String?>[];
    final asked = <bool>[];
    final client = SyncClient(
      baseUrl: Uri.parse('https://s.test/'),
      getJws: (force) async {
        asked.add(force);
        return force ? 'moi' : 'cu';
      },
      httpClient: MockClient((req) async {
        auth.add(req.headers['Authorization']);
        expect(req.url.toString(), 'https://s.test/v1/records?since=0&limit=500');
        return jsonRes(401, {'error': 'invalid_token', 'reason': 'stale'});
      }),
    );
    await expectLater(
      client.pullRecords(),
      throwsA(isA<SyncHttpException>().having((e) => e.reason, 'reason', 'stale')),
    );
    expect(asked, [false, true]);
    expect(auth, ['Bearer cu', 'Bearer moi']);
  });

  test('402 ⇒ ProRequiredException, không thử lại', () async {
    var calls = 0;
    final client = SyncClient(
      baseUrl: Uri.parse('https://s.test'),
      getJws: (_) async => 'j',
      httpClient: MockClient((_) async {
        calls++;
        return jsonRes(402, {'error': 'pro_required', 'reason': 'no_pro'});
      }),
    );
    await expectLater(
      client.account(),
      throwsA(isA<ProRequiredException>().having((e) => e.reason, 'reason', 'no_pro')),
    );
    expect(calls, 1);
  });

  test('503 mang Retry-After', () async {
    final client = SyncClient(
      baseUrl: Uri.parse('https://s.test'),
      getJws: (_) async => 'j',
      httpClient: MockClient((_) async => jsonRes(503, {'error': 'busy'}, {'retry-after': '5'})),
    );
    await expectLater(
      client.listFiles(),
      throwsA(
        isA<SyncHttpException>().having((e) => e.retryAfter, 'retryAfter', 5).having((e) => e.code, 'code', 'busy'),
      ),
    );
  });

  test('DPoP: Authorization DPoP + bằng chứng, htu không có query; X-Tsu-Installation', () async {
    final seen = <String>[];
    late http.BaseRequest sent;
    final client = SyncClient(
      baseUrl: Uri.parse('https://s.test'),
      getJws: (_) async => 'jws',
      installationId: 'AAAAAAAAAAAAAAAAAAAAAA',
      dpop: (m, u, j) async {
        seen.add('$m $u $j');
        return 'proof';
      },
      httpClient: MockClient((req) async {
        sent = req;
        return jsonRes(200, {'items': <Object>[], 'next': 0, 'more': false});
      }),
    );
    await client.pullRecords(since: 7, limit: 10);
    expect(seen, ['GET https://s.test/v1/records jws']);
    expect(sent.headers['Authorization'], 'DPoP jws');
    expect(sent.headers['DPoP'], 'proof');
    expect(sent.headers['X-Tsu-Installation'], 'AAAAAAAAAAAAAAAAAAAAAA');
  });

  test('từ chối id chứa bản rõ và mã cài đặt sai', () {
    expect(
      () => SyncClient(baseUrl: Uri.parse('https://s.test'), getJws: (_) async => 'j', installationId: 'ngắn'),
      throwsArgumentError,
    );
    final client = SyncClient(
      baseUrl: Uri.parse('https://s.test'),
      getJws: (_) async => 'j',
      httpClient: MockClient((_) async => http.Response('', 500)),
    );
    expect(() => client.getFile('hoá đơn.jpg'), throwsArgumentError);
  });

  test('SyncSession: đẩy bản ghi mã hoá, mở lại được, tráo id thì không mở được; bia mộ', () async {
    late Map<String, Object?> body;
    final keys = c.createKeys('mật khẩu đồng bộ thử', ops: TsuSyncCrypto.minOps, mem: TsuSyncCrypto.minMem);
    final s = SyncSession(
      SyncClient(
        baseUrl: Uri.parse('https://s.test'),
        getJws: (_) async => 'j',
        httpClient: MockClient((req) async {
          body = jsonDecode(req.body) as Map<String, Object?>;
          return jsonRes(200, {'results': <Object>[], 'rev': 2});
        }),
      ),
      c,
      keys,
      'tsudev-test',
    );
    final payload = await s.sealRecord('r1', Uint8List.fromList(utf8.encode('bí mật')));
    await s.client.pushRecords([
      PushItem(id: 'r1', baseRev: 0, payload: payload),
      const PushItem(id: 'r2', deleted: true),
    ]);
    final items = (body['items']! as List).cast<Map<String, Object?>>();
    expect(items[0], {'id': 'r1', 'base_rev': 0, 'payload': payload});
    expect(items[1], {'id': 'r2', 'deleted': true});
    final opened = await s.openRecord(PullItem(id: 'r1', rev: 1, deleted: false, payload: payload));
    expect(utf8.decode(opened!), 'bí mật');
    expect(await s.openRecord(const PullItem(id: 'r2', rev: 2, deleted: true)), isNull);
    await expectLater(
      s.openRecord(PullItem(id: 'r3', rev: 1, deleted: false, payload: payload)),
      throwsA(isA<TsuSyncCryptoException>()),
    );
  });

  test('putPlainFile gửi X-Tsu-Digest = SHA-256 bản mã; getPlainFile mở lại được', () async {
    final keys = c.createKeys('mật khẩu đồng bộ thử', ops: TsuSyncCrypto.minOps, mem: TsuSyncCrypto.minMem);
    Uint8List? stored;
    final s = SyncSession(
      SyncClient(
        baseUrl: Uri.parse('https://s.test'),
        getJws: (_) async => 'j',
        httpClient: MockClient((req) async {
          if (req.method == 'PUT') {
            stored = req.bodyBytes;
            expect(req.headers['X-Tsu-Digest'], isNotEmpty);
            return jsonRes(201, {'id': 'f1', 'status': 'applied', 'rev': 1});
          }
          return http.Response.bytes(stored!, 200);
        }),
      ),
      c,
      keys,
      'tsudev-test',
    );
    await s.putPlainFile('f1', Uint8List(70000));
    expect((await s.getPlainFile('f1')).length, 70000);
  });
}
