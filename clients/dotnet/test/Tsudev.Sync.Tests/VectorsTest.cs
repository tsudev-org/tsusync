// Vector đối chiếu conformance/vectors-v1.json - CÙNG khuôn với clients/dart/test/vectors_test.dart, clients/rust,
// test TypeScript và conformance/verify_libsodium.py.
using System.Text.Json.Nodes;
using Tsudev.Sync;

namespace Tsudev.Sync.Tests;

public class VectorsTest
{
    private const int Full = TsuSyncCrypto.ChunkBytes + TsuSyncCrypto.ABytes;
    private const int Head = TsuSyncCrypto.PrefixBytes + TsuSyncCrypto.HeaderBytes;

    private static readonly JsonObject V = Load();

    private static JsonObject Load()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "conformance", "vectors-v1.json")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return JsonNode.Parse(File.ReadAllText(Path.Combine(dir.FullName, "conformance", "vectors-v1.json")))!
            .AsObject();
    }

    private static byte[] Pattern(int n) => Enumerable.Range(0, n).Select(i => (byte)((i * 31 + 7) & 0xff)).ToArray();
    private static string S(JsonNode? n, string k) => n![k]!.GetValue<string>();
    private static CipherKind KindOf(string s) => s == "rec" ? CipherKind.Rec : s == "file" ? CipherKind.File : throw new ArgumentException(s);
    private static JsonArray Arr(JsonNode? n) => n!.AsArray();
    private static byte[] DataKey => TsuSyncCrypto.FromB64u(S(V["stream"], "data_key"));

    /// <summary>Áp đột biến của must_fail - CÙNG ngữ nghĩa với verify_libsodium.py và test Dart/TypeScript/Rust.</summary>
    private static byte[] Mutate(byte[] src, JsonObject m)
    {
        var ct = new List<byte>(src);
        if (m["flip"] is { } flip)
        {
            var f = flip.GetValue<int>();
            ct[f < 0 ? ct.Count + f : f] ^= 1;
        }
        if (m["truncate"] is { } t) ct.RemoveRange(ct.Count - t.GetValue<int>(), t.GetValue<int>());
        if (m["keep"] is { } keep) ct.RemoveRange(keep.GetValue<int>(), ct.Count - keep.GetValue<int>());
        if (m["drop_last_chunk"]?.GetValue<bool>() == true)
        {
            var n = Math.Max(1, (ct.Count - Head + Full - 1) / Full);
            ct.RemoveRange(Head + (n - 1) * Full, ct.Count - (Head + (n - 1) * Full));
        }
        if (m["append_b64"] is { } a) ct.AddRange(TsuSyncCrypto.FromB64u(a.GetValue<string>()));
        var arr = ct.ToArray();
        if (m["swap_chunks"] is JsonArray sw)
        {
            int x = sw[0]!.GetValue<int>(), y = sw[1]!.GetValue<int>();
            var cx = arr.AsSpan(Head + x * Full, Full).ToArray();
            var cy = arr.AsSpan(Head + y * Full, Full).ToArray();
            cy.CopyTo(arr, Head + x * Full);
            cx.CopyTo(arr, Head + y * Full);
        }
        if (m["set_byte"] is JsonArray sb) arr[sb[0]!.GetValue<int>()] = (byte)sb[1]!.GetValue<int>();
        return arr;
    }

    [Fact]
    public void Dung_dinh_dang() => Assert.Equal("tsusync-stream-v1", S(V, "format"));

    [Fact]
    public void Mo_duoc()
    {
        var cases = Arr(V["stream"]!["cases"]);
        Assert.True(cases.Count >= 7);
        foreach (var c in cases)
        {
            var expected = c!["plaintext_pattern"] is { } p
                ? Pattern(p.GetValue<int>())
                : TsuSyncCrypto.FromB64u(S(c, "plaintext_b64"));
            var ctx = new CipherContext(S(c, "namespace"), KindOf(S(c, "kind")), S(c, "id"));
            var got = TsuSyncCrypto.Decrypt(DataKey, ctx, TsuSyncCrypto.FromB64u(S(c, "ciphertext")));
            Assert.True(expected.AsSpan().SequenceEqual(got), S(c, "name"));
        }
    }

    [Fact]
    public void Tu_choi()
    {
        var cases = Arr(V["stream"]!["cases"]);
        var fails = Arr(V["stream"]!["must_fail"]);
        Assert.True(fails.Count >= 16);
        foreach (var f in fails)
        {
            var b = cases.First(x => S(x, "name") == S(f, "base"))!;
            var m = f!["mutation"]!.AsObject();
            string Over(string k) => m["context"]?[k]?.GetValue<string>() ?? S(b, k);
            var ctx = new CipherContext(Over("namespace"), KindOf(Over("kind")), Over("id"));
            var key = m["key"] is { } k ? TsuSyncCrypto.FromB64u(k.GetValue<string>()) : DataKey;
            var ct = Mutate(TsuSyncCrypto.FromB64u(S(b, "ciphertext")), m);
            var e = Record.Exception(() => TsuSyncCrypto.Decrypt(key, ctx, ct));
            Assert.True(e is TsuSyncCryptoException, $"{S(f, "name")}: lẽ ra phải thất bại ({e?.GetType().Name})");
        }
    }

    [Fact]
    public void Suy_khoa()
    {
        var kdf = V["kdf"]!;
        foreach (var k in Arr(kdf["cases"]))
        {
            var (dk, check) = TsuSyncCrypto.DeriveRaw(S(k, "password"), TsuSyncCrypto.FromB64u(S(k, "salt")),
                k!["ops"]!.GetValue<long>(), k["mem"]!.GetValue<long>());
            Assert.Equal(S(k, "data_key"), TsuSyncCrypto.B64u(dk));
            Assert.Equal(S(k, "check"), TsuSyncCrypto.B64u(check));
        }
        foreach (var k in Arr(kdf["reject"]))
        {
            var e = Record.Exception(() => TsuSyncCrypto.DeriveRaw(S(k, "password"),
                TsuSyncCrypto.FromB64u(S(k, "salt")), k!["ops"]!.GetValue<long>(), k["mem"]!.GetValue<long>()));
            if (S(k, "error") == "weak_password") Assert.IsType<WeakPasswordException>(e);
            else Assert.IsType<TsuSyncCryptoException>(e);
        }
        foreach (var k in Arr(kdf["unlock"]))
        {
            if (k!["error"] is not null)
            {
                Assert.Throws<WrongPasswordException>(() => TsuSyncCrypto.UnlockKeys(S(k, "password"), k["params"]));
                continue;
            }
            using var keys = TsuSyncCrypto.UnlockKeys(S(k, "password"), k["params"]);
            Assert.Equal(S(k, "data_key"), TsuSyncCrypto.B64u(keys.DataKey));
            Assert.True(JsonNode.DeepEquals(keys.Params.ToJson(), k["params"]), S(k, "name"));
        }
    }

    [Theory]
    [InlineData(CipherKind.Rec, 0)]
    [InlineData(CipherKind.Rec, 1)]
    [InlineData(CipherKind.File, TsuSyncCrypto.ChunkBytes - 1)]
    [InlineData(CipherKind.File, TsuSyncCrypto.ChunkBytes)]
    [InlineData(CipherKind.File, 3 * TsuSyncCrypto.ChunkBytes + 7)]
    public void Khu_hoi(CipherKind kind, int n)
    {
        var ctx = new CipherContext("tsudev-test", kind, "x1");
        var ct = TsuSyncCrypto.Encrypt(DataKey, ctx, Pattern(n));
        Assert.Equal(Pattern(n), TsuSyncCrypto.Decrypt(DataKey, ctx, ct));
        Assert.NotEqual(ct, TsuSyncCrypto.Encrypt(DataKey, ctx, Pattern(n)));
    }

    [Theory]
    [InlineData("ns", "tên tệp.pdf")]
    [InlineData("", "a")]
    [InlineData("a|b", "c")]
    public void Ngu_canh_sai_dinh_dang_bi_tu_choi(string ns, string id) =>
        Assert.Throws<TsuSyncCryptoException>(() =>
            TsuSyncCrypto.Encrypt(DataKey, new CipherContext(ns, CipherKind.Rec, id), Pattern(1)));

    [Fact]
    public void Tao_khoa_va_mo_khoa_khu_hoi_qua_json()
    {
        const string pw = "mật khẩu đủ dài 2026";
        using var k = TsuSyncCrypto.CreateKeys(pw, TsuSyncCrypto.MinOps, TsuSyncCrypto.MinMem);
        var json = JsonNode.Parse(k.Params.ToJson().ToJsonString())!.AsObject();
        using (var u = TsuSyncCrypto.UnlockKeys(pw, json)) Assert.Equal(k.DataKey, u.DataKey);
        var weak = json.DeepClone();
        weak["ops"] = 1;
        Assert.Throws<TsuSyncCryptoException>(() => TsuSyncCrypto.UnlockKeys(pw, weak));
        Assert.Throws<WrongPasswordException>(() => TsuSyncCrypto.UnlockKeys("mật khẩu sai rồi 2026", json));
    }

    [Fact]
    public void Base64url_nghiem()
    {
        for (var n = 0; n < 8; n++) Assert.Equal(Pattern(n), TsuSyncCrypto.FromB64u(TsuSyncCrypto.B64u(Pattern(n))));
        Assert.Equal("-_8", TsuSyncCrypto.B64u([0xfb, 0xff]));
        foreach (var bad in new[] { "A", "AB=", "a+b", "AB/C", "-_9" })
            Assert.Throws<TsuSyncCryptoException>(() => TsuSyncCrypto.FromB64u(bad));
    }
}
