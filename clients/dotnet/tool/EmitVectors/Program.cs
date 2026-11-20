// Phát vector do CHÍNH thư viện .NET mã hoá/suy khoá, cùng khuôn conformance/vectors-v1.json, để CI kiểm chiều ngược
// lại bằng libsodium độc lập: `dotnet run --project tool/EmitVectors > /tmp/dotnet.json`
// rồi `python3 -I ../../conformance/verify_libsodium.py /tmp/dotnet.json`.
using System.Text.Json.Nodes;
using Tsudev.Sync;

static byte[] Pattern(int n) => Enumerable.Range(0, n).Select(i => (byte)((i * 31 + 7) & 0xff)).ToArray();

var raw = Enumerable.Range(0, 32).Select(i => (byte)(0x55 + i)).ToArray();
var cases = new JsonArray();
foreach (var (name, kind, id, n) in new[]
         {
             ("dotnet-rec-empty", CipherKind.Rec, "r0", 0),
             ("dotnet-rec-300", CipherKind.Rec, "r1", 300),
             ("dotnet-file-two-chunks", CipherKind.File, "f1", 65536),
             ("dotnet-file-three-chunks", CipherKind.File, "f2", 2 * 65536 + 100),
         })
{
    var ct = TsuSyncCrypto.Encrypt(raw, new CipherContext("tsudev-test", kind, id), Pattern(n));
    cases.Add(new JsonObject
    {
        ["name"] = name,
        ["namespace"] = "tsudev-test",
        ["kind"] = TsuSyncCrypto.KindName(kind),
        ["id"] = id,
        ["plaintext_pattern"] = n,
        ["ciphertext"] = TsuSyncCrypto.B64u(ct),
    });
}
var salt = Enumerable.Range(0, 16).Select(i => (byte)(0xF0 - i)).ToArray();
const string pw = "Mật khẩu đồng bộ năm 2026";
var (dk, check) = TsuSyncCrypto.DeriveRaw(pw, salt, TsuSyncCrypto.MinOps, TsuSyncCrypto.MinMem);
using var created = TsuSyncCrypto.CreateKeys(pw, TsuSyncCrypto.MinOps, TsuSyncCrypto.MinMem);
var output = new JsonObject
{
    ["format"] = "tsusync-stream-v1",
    ["stream"] = new JsonObject { ["data_key"] = TsuSyncCrypto.B64u(raw), ["cases"] = cases },
    ["kdf"] = new JsonObject
    {
        ["cases"] = new JsonArray(new JsonObject
        {
            ["name"] = "dotnet-kdf",
            ["password"] = pw,
            ["salt"] = TsuSyncCrypto.B64u(salt),
            ["ops"] = TsuSyncCrypto.MinOps,
            ["mem"] = TsuSyncCrypto.MinMem,
            ["data_key"] = TsuSyncCrypto.B64u(dk),
            ["check"] = TsuSyncCrypto.B64u(check),
        }),
        ["unlock"] = new JsonArray(new JsonObject
        {
            ["name"] = "dotnet-created",
            ["params"] = created.Params.ToJson(),
            ["password"] = pw,
            ["data_key"] = TsuSyncCrypto.B64u(created.DataKey),
        }),
    },
};
Console.WriteLine(output.ToJsonString());
