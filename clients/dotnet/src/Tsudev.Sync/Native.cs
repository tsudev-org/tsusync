using System.Runtime.InteropServices;

namespace Tsudev.Sync;

/// <summary>P/Invoke vào libsodium C (gói NuGet <c>libsodium</c> chính chủ) - đúng các hàm mà ADR-0003 dùng.</summary>
internal static unsafe partial class Native
{
    private const string Lib = "libsodium";

    [LibraryImport(Lib)]
    internal static partial int sodium_init();

    [LibraryImport(Lib)]
    internal static partial int crypto_pwhash(byte* output, ulong outlen, byte* passwd, ulong passwdlen, byte* salt,
        ulong opslimit, nuint memlimit, int alg);

    [LibraryImport(Lib)]
    internal static partial int crypto_pwhash_alg_argon2id13();

    [LibraryImport(Lib)]
    internal static partial int crypto_kdf_derive_from_key(byte* subkey, nuint subkeyLen, ulong subkeyId, byte* ctx,
        byte* key);

    [LibraryImport(Lib)]
    internal static partial nuint crypto_secretstream_xchacha20poly1305_statebytes();

    [LibraryImport(Lib)]
    internal static partial int crypto_secretstream_xchacha20poly1305_init_push(byte* state, byte* header, byte* key);

    [LibraryImport(Lib)]
    internal static partial int crypto_secretstream_xchacha20poly1305_push(byte* state, byte* c, ulong* clen, byte* m,
        ulong mlen, byte* ad, ulong adlen, byte tag);

    [LibraryImport(Lib)]
    internal static partial int crypto_secretstream_xchacha20poly1305_init_pull(byte* state, byte* header, byte* key);

    [LibraryImport(Lib)]
    internal static partial int crypto_secretstream_xchacha20poly1305_pull(byte* state, byte* m, ulong* mlen,
        byte* tag, byte* c, ulong clen, byte* ad, ulong adlen);

    [LibraryImport(Lib)]
    internal static partial int sodium_pad(nuint* paddedLen, byte* buf, nuint unpaddedLen, nuint blocksize,
        nuint maxLen);

    [LibraryImport(Lib)]
    internal static partial int sodium_unpad(nuint* unpaddedLen, byte* buf, nuint paddedLen, nuint blocksize);

    [LibraryImport(Lib)]
    internal static partial void randombytes_buf(byte* buf, nuint size);

    [LibraryImport(Lib)]
    internal static partial int sodium_memcmp(byte* a, byte* b, nuint len);

    [LibraryImport(Lib)]
    internal static partial void sodium_memzero(byte* p, nuint len);

    internal static void Zero(Span<byte> s)
    {
        fixed (byte* p = s) sodium_memzero(p, (nuint)s.Length);
    }
}
