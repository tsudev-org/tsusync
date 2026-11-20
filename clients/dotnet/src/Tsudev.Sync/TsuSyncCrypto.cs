// Mã hoá đầu cuối của TsuDEV Sync - định dạng `TS 01` (ADR-0003). Máy chủ không bao giờ thấy khoá hay bản rõ.
// Cùng API và ngữ nghĩa với clients/ts/src/crypto.ts, clients/dart và clients/rust; mọi thư viện cùng qua
// conformance/vectors-v1.json và libsodium C độc lập (conformance/verify_libsodium.py).
//
// - Khoá gốc = Argon2id13(NFKC(mật khẩu đồng bộ), muối 16 B, ≥ 3 lượt / 64 MiB) - cùng thông số qulythuchi ADR-0007.
// - Khoá dữ liệu = crypto_kdf(gốc, id 1, "TSUSYNC1"); mã kiểm mật khẩu = crypto_kdf(gốc, id 2, "TSUSYNC1", 16 B).
// - Bản mã = 'T' 'S' 01 <loại> ‖ header secretstream 24 B ‖ các khối secretstream XChaCha20-Poly1305
//   (bản rõ đã sodium_pad, cắt khối 64 KiB, khối cuối mang TAG_FINAL). AAD mỗi khối = 4 byte đầu ‖ ngữ cảnh.
//
// Đổi BẤT KỲ điểm nào ⇒ định dạng mới + ADR mới + vector mới (`conformance/`), dữ liệu cũ vẫn phải đọc được.
using System.Text;
using System.Text.Json.Nodes;

namespace Tsudev.Sync;

/// <summary>Loại bản mã - nằm trong byte thứ tư của tiền tố và trong ngữ cảnh.</summary>
public enum CipherKind
{
    Rec = 1,
    File = 2,
}

/// <summary>Ngữ cảnh gắn vào AAD: bản mã chỉ mở được đúng sản phẩm + loại + định danh đã tạo ra nó.</summary>
public sealed record CipherContext(string Namespace, CipherKind Kind, string Id);

/// <summary>Giải mã/mở khoá thất bại. Thông điệp cố ý chung - không nói khoá sai hay dữ liệu bị sửa.</summary>
public class TsuSyncCryptoException : Exception
{
    public TsuSyncCryptoException() : base("Không mở được dữ liệu mã hoá.") { }
    public TsuSyncCryptoException(string message) : base(message) { }
    public TsuSyncCryptoException(string message, Exception inner) : base(message, inner) { }
}

public sealed class WeakPasswordException : Exception
{
    public WeakPasswordException() : base($"Mật khẩu đồng bộ cần ít nhất {TsuSyncCrypto.MinPasswordLength} ký tự.") { }
    public WeakPasswordException(string message) : base(message) { }
    public WeakPasswordException(string message, Exception inner) : base(message, inner) { }
}

public sealed class WrongPasswordException : Exception
{
    public WrongPasswordException() : base("Mật khẩu đồng bộ không đúng.") { }
    public WrongPasswordException(string message) : base(message) { }
    public WrongPasswordException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Tham số KDF lưu kèm dữ liệu (không bí mật). JSON <c>{"v":1,"alg":"argon2id13",salt,ops,mem,check}</c>.</summary>
public sealed record KdfParams(string Salt, long Ops, long Mem, string Check)
{
    public JsonObject ToJson() => new()
    {
        ["v"] = 1,
        ["alg"] = "argon2id13",
        ["salt"] = Salt,
        ["ops"] = Ops,
        ["mem"] = Mem,
        ["check"] = Check,
    };
}

/// <summary>Khoá đồng bộ đã mở. <see cref="DataKey"/> 32 B - giữ trong bộ nhớ, KHÔNG gửi đi; Dispose xoá về 0.</summary>
public sealed class SyncKeys(byte[] dataKey, KdfParams kdfParams) : IDisposable
{
    public byte[] DataKey { get; } = dataKey;
    public KdfParams Params { get; } = kdfParams;
    public void Dispose() => Native.Zero(DataKey);
}

public static unsafe class TsuSyncCrypto
{
    public const int FormatVersion = 1;
    public const int ChunkBytes = 64 * 1024;
    public const int HeaderBytes = 24;
    public const int ABytes = 17;
    public const int PrefixBytes = 4;
    public const string KdfContext = "TSUSYNC1";
    public const int SaltBytes = 16;
    public const int MinPasswordLength = 10;

    /// <summary>Mặc định 3 lượt / 64 MiB; sàn khi mở khoá 2 lượt / 19 MiB (OWASP); trần chống máy chủ độc.</summary>
    public const long DefaultOps = 3, DefaultMem = 64L * 1024 * 1024;
    public const long MinOps = 2, MinMem = 19L * 1024 * 1024;
    public const long MaxOps = 16, MaxMem = 1024L * 1024 * 1024;

    private const byte TagMessage = 0;
    private const byte TagFinal = 3;
    private static readonly int StateBytes;

    static TsuSyncCrypto()
    {
        if (Native.sodium_init() < 0) throw new InvalidOperationException("sodium_init thất bại.");
        StateBytes = (int)Native.crypto_secretstream_xchacha20poly1305_statebytes();
    }

    public static int PadBlock(CipherKind kind) => kind == CipherKind.Rec ? 256 : 4096;

    public static string KindName(CipherKind kind) => kind switch
    {
        CipherKind.Rec => "rec",
        CipherKind.File => "file",
        _ => throw new TsuSyncCryptoException("Ngữ cảnh mã hoá không hợp lệ."),
    };

    // ------------------------------------------------------------ base64url không đệm (như libsodium + máy chủ)

    private const string B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    public static string B64u(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder((bytes.Length + 2) / 3 * 4);
        for (var i = 0; i < bytes.Length; i += 3)
        {
            var len = Math.Min(3, bytes.Length - i);
            var n = bytes[i] << 16 | (len > 1 ? bytes[i + 1] << 8 : 0) | (len > 2 ? bytes[i + 2] : 0);
            for (var j = 0; j <= len; j++) sb.Append(B64[(n >> (18 - 6 * j)) & 63]);
        }
        return sb.ToString();
    }

    /// <summary>Từ chối ký tự lạ, độ dài không thể có và bit thừa khác 0 (như <c>sodium_base642bin</c>).</summary>
    public static byte[] FromB64u(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        var output = new List<byte>(s.Length * 3 / 4);
        int acc = 0, bits = 0;
        foreach (var ch in s)
        {
            var v = B64.IndexOf(ch, StringComparison.Ordinal);
            if (v < 0) throw new TsuSyncCryptoException("Chuỗi base64url không hợp lệ.");
            acc = (acc << 6 | v) & 0xFFFF;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)(acc >> bits));
            }
        }
        if (bits > 4 || (acc & ((1 << bits) - 1)) != 0) throw new TsuSyncCryptoException("Chuỗi base64url không hợp lệ.");
        return [.. output];
    }

    // ------------------------------------------------------------ suy khoá

    /// <summary>Mật khẩu chuẩn hoá NFKC; đếm độ dài theo code point (như TypeScript <c>[...s].length</c>).</summary>
    public static string NormalizePassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        string n;
        try
        {
            n = password.Normalize(NormalizationForm.FormKC);
        }
        catch (ArgumentException e)
        {
            throw new TsuSyncCryptoException("Mật khẩu chứa ký tự không hợp lệ.", e);
        }
        if (n.EnumerateRunes().Count() < MinPasswordLength) throw new WeakPasswordException();
        return n;
    }

    private static void CheckRange(long ops, long mem)
    {
        if (ops < MinOps || mem < MinMem) throw new TsuSyncCryptoException("Tham số KDF yếu hơn mức tối thiểu.");
        if (ops > MaxOps || mem > MaxMem) throw new TsuSyncCryptoException("Tham số KDF vượt trần.");
    }

    /// <summary>Suy khoá - hàm thuần, dùng cho cả tạo mới, mở khoá và vector đối chiếu.</summary>
    public static (byte[] DataKey, byte[] Check) DeriveRaw(string password, ReadOnlySpan<byte> salt, long ops, long mem)
    {
        CheckRange(ops, mem);
        if (salt.Length != SaltBytes) throw new TsuSyncCryptoException("Muối KDF phải dài 16 byte.");
        var pw = Encoding.UTF8.GetBytes(NormalizePassword(password));
        var root = new byte[32];
        var dataKey = new byte[32];
        var check = new byte[16];
        var ctx = Encoding.ASCII.GetBytes(KdfContext);
        try
        {
            fixed (byte* r = root, p = pw, s = salt, d = dataKey, c = check, x = ctx)
            {
                if (Native.crypto_pwhash(r, 32, p, (ulong)pw.Length, s, (ulong)ops, (nuint)mem,
                        Native.crypto_pwhash_alg_argon2id13()) != 0)
                    throw new TsuSyncCryptoException("Không suy được khoá (thiếu bộ nhớ?).");
                if (Native.crypto_kdf_derive_from_key(d, 32, 1, x, r) != 0 ||
                    Native.crypto_kdf_derive_from_key(c, 16, 2, x, r) != 0)
                    throw new TsuSyncCryptoException();
            }
            return (dataKey, check);
        }
        finally
        {
            Native.Zero(root);
            Native.Zero(pw);
        }
    }

    /// <summary>Tạo khoá mới cho tài khoản đồng bộ (lần đầu bật đồng bộ trên thiết bị đầu tiên).</summary>
    public static SyncKeys CreateKeys(string password, long ops = DefaultOps, long mem = DefaultMem)
    {
        var salt = new byte[SaltBytes];
        fixed (byte* s = salt) Native.randombytes_buf(s, SaltBytes);
        var (dataKey, check) = DeriveRaw(password, salt, ops, mem);
        return new SyncKeys(dataKey, new KdfParams(B64u(salt), ops, mem, B64u(check)));
    }

    /// <summary>Mở khoá trên thiết bị khác bằng tham số đã lưu (JSON). Sai mật khẩu ⇒ <see cref="WrongPasswordException"/>.</summary>
    public static SyncKeys UnlockKeys(string password, JsonNode? kdfParams)
    {
        var p = ParseKdfParams(kdfParams);
        var (dataKey, check) = DeriveRaw(password, FromB64u(p.Salt), p.Ops, p.Mem);
        var expected = FromB64u(p.Check);
        bool ok;
        fixed (byte* e = expected, c = check)
            ok = expected.Length == check.Length && Native.sodium_memcmp(e, c, (nuint)check.Length) == 0;
        if (!ok)
        {
            Native.Zero(dataKey);
            throw new WrongPasswordException();
        }
        return new SyncKeys(dataKey, p);
    }

    /// <summary>Đọc tham số KDF từ JSON không tin cậy (máy chủ trả về).</summary>
    public static KdfParams ParseKdfParams(JsonNode? raw)
    {
        if (raw is not JsonObject o || Int(o["v"]) != 1 || Str(o["alg"]) != "argon2id13")
            throw new TsuSyncCryptoException("Tham số KDF không hỗ trợ.");
        if (Str(o["salt"]) is not { } salt || Str(o["check"]) is not { } check || Int(o["ops"]) is not { } ops ||
            Int(o["mem"]) is not { } mem)
            throw new TsuSyncCryptoException("Tham số KDF không hợp lệ.");
        CheckRange(ops, mem);
        return new KdfParams(salt, ops, mem, check);

        static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
        static long? Int(JsonNode? n) => n is JsonValue v && v.TryGetValue<long>(out var x) ? x : null;
    }

    // ------------------------------------------------------------ mã hoá

    private static bool Safe(string s) =>
        s.Length is >= 1 and <= 128 && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '~' or ':' or '-');

    private static byte[] Prefix(CipherKind kind) => [0x54, 0x53, FormatVersion, (byte)kind];

    private static byte[] Aad(CipherContext ctx)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        if (!Safe(ctx.Namespace) || !Safe(ctx.Id) || !Enum.IsDefined(ctx.Kind))
            throw new TsuSyncCryptoException("Ngữ cảnh mã hoá không hợp lệ.");
        return [.. Prefix(ctx.Kind), .. Encoding.UTF8.GetBytes($"tsusync|v1|{ctx.Namespace}|{KindName(ctx.Kind)}|{ctx.Id}")];
    }

    /// <summary>Mã hoá một bản ghi/tệp. Mỗi lần gọi ra bản mã khác nhau (header ngẫu nhiên).</summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> dataKey, CipherContext ctx, ReadOnlySpan<byte> plaintext)
    {
        if (dataKey.Length != 32) throw new TsuSyncCryptoException("Khoá dữ liệu phải dài 32 byte.");
        var ad = Aad(ctx);
        var block = PadBlock(ctx.Kind);
        var padded = new byte[plaintext.Length + block - plaintext.Length % block];
        plaintext.CopyTo(padded);
        var state = new byte[StateBytes];
        try
        {
            nuint plen;
            fixed (byte* b = padded)
            {
                if (Native.sodium_pad(&plen, b, (nuint)plaintext.Length, (nuint)block, (nuint)padded.Length) != 0 ||
                    plen != (nuint)padded.Length)
                    throw new TsuSyncCryptoException();
            }
            var chunks = (padded.Length + ChunkBytes - 1) / ChunkBytes;
            var output = new byte[PrefixBytes + HeaderBytes + padded.Length + chunks * ABytes];
            Prefix(ctx.Kind).CopyTo(output, 0);
            fixed (byte* st = state, k = dataKey, o = output, b = padded, a = ad)
            {
                if (Native.crypto_secretstream_xchacha20poly1305_init_push(st, o + PrefixBytes, k) != 0)
                    throw new TsuSyncCryptoException();
                var pos = PrefixBytes + HeaderBytes;
                for (var i = 0; i < chunks; i++)
                {
                    var off = i * ChunkBytes;
                    var len = Math.Min(ChunkBytes, padded.Length - off);
                    var tag = i == chunks - 1 ? TagFinal : TagMessage;
                    if (Native.crypto_secretstream_xchacha20poly1305_push(st, o + pos, null, b + off, (ulong)len, a,
                            (ulong)ad.Length, tag) != 0)
                        throw new TsuSyncCryptoException();
                    pos += len + ABytes;
                }
            }
            return output;
        }
        finally
        {
            Native.Zero(padded);
            Native.Zero(state);
        }
    }

    /// <summary>Giải mã. Mọi sai lệch (khoá, ngữ cảnh, cắt cụt, nối thêm, tráo khối, đệm) ⇒ <see cref="TsuSyncCryptoException"/>.</summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> dataKey, CipherContext ctx, ReadOnlySpan<byte> ciphertext)
    {
        if (dataKey.Length != 32) throw new TsuSyncCryptoException();
        var ad = Aad(ctx);
        const int head = PrefixBytes + HeaderBytes;
        if (ciphertext.Length < head + ABytes || !ciphertext[..PrefixBytes].SequenceEqual(Prefix(ctx.Kind)))
            throw new TsuSyncCryptoException();
        var body = ciphertext[head..];
        const int full = ChunkBytes + ABytes;
        var n = Math.Max(1, (body.Length + full - 1) / full);
        // Khối cuối phải có ít nhất ABYTES; mọi khối trước đó phải đầy.
        if (body.Length - (n - 1) * full < ABytes) throw new TsuSyncCryptoException();
        var output = new byte[body.Length - n * ABytes];
        var state = new byte[StateBytes];
        try
        {
            nuint unpadded;
            fixed (byte* st = state, k = dataKey, c = ciphertext, o = output, a = ad)
            {
                if (Native.crypto_secretstream_xchacha20poly1305_init_pull(st, c + PrefixBytes, k) != 0)
                    throw new TsuSyncCryptoException();
                var pos = 0;
                for (var i = 0; i < n; i++)
                {
                    var off = head + i * full;
                    var len = Math.Min(full, ciphertext.Length - off);
                    ulong mlen;
                    byte tag;
                    if (Native.crypto_secretstream_xchacha20poly1305_pull(st, o + pos, &mlen, &tag, c + off,
                            (ulong)len, a, (ulong)ad.Length) != 0)
                        throw new TsuSyncCryptoException();
                    // TAG_FINAL đúng ở khối cuối và CHỈ ở đó: chống cắt cụt và chống nối thêm.
                    if ((tag == TagFinal) != (i == n - 1) || (tag != TagFinal && tag != TagMessage))
                        throw new TsuSyncCryptoException();
                    pos += (int)mlen;
                }
                if (Native.sodium_unpad(&unpadded, o, (nuint)pos, (nuint)PadBlock(ctx.Kind)) != 0)
                    throw new TsuSyncCryptoException();
            }
            return output.AsSpan(0, (int)unpadded).ToArray();
        }
        finally
        {
            Native.Zero(output);
            Native.Zero(state);
        }
    }
}
