using System.Text;
using PasswordPorter.KeePass.Crypto;

namespace PasswordPorter.KeePass.Kdbx;

/// <summary>The file is not a valid KDBX database (corrupt, truncated or an unsupported variant).</summary>
public class KdbxFormatException(string message) : Exception(message);

/// <summary>The password and/or key file do not open the database.</summary>
public sealed class KdbxInvalidKeyException()
    : Exception("The master key is wrong (password or key file), or the file is corrupt.");

/// <summary>Bounds-checked little-endian reader over a byte array.</summary>
internal sealed class ByteReader(byte[] data, int position = 0)
{
    public int Position { get; private set; } = position;

    public int Remaining => data.Length - Position;

    ReadOnlySpan<byte> Take(int count)
    {
        if (count < 0 || count > Remaining)
            throw new KdbxFormatException("The file is truncated or corrupt.");
        var span = data.AsSpan(Position, count);
        Position += count;
        return span;
    }

    public byte ReadByte() => Take(1)[0];

    public ushort ReadUInt16() => BinaryPrimitives.ReadUInt16LittleEndian(Take(2));

    public uint ReadUInt32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));

    public int ReadInt32() => BinaryPrimitives.ReadInt32LittleEndian(Take(4));

    public byte[] ReadBytes(int count) => Take(count).ToArray();
}

/// <summary>
/// KDBX 4 "VariantDictionary": typed key/value pairs used for KDF parameters and public custom data.
/// </summary>
internal sealed class VariantDictionary
{
    internal enum ValueType : byte
    {
        UInt32 = 0x04,
        UInt64 = 0x05,
        Bool = 0x08,
        Int32 = 0x0C,
        Int64 = 0x0D,
        String = 0x18,
        ByteArray = 0x42,
    }

    readonly record struct Item(ValueType Type, object Value);

    const ushort Version = 0x0100;
    readonly List<string> order = [];
    readonly Dictionary<string, Item> items = new(StringComparer.Ordinal);

    void Set(string key, ValueType type, object value)
    {
        if (!items.ContainsKey(key))
            order.Add(key);
        items[key] = new(type, value);
    }

    public void SetUInt32(string key, uint value) => Set(key, ValueType.UInt32, value);
    public void SetUInt64(string key, ulong value) => Set(key, ValueType.UInt64, value);
    public void SetBytes(string key, byte[] value) => Set(key, ValueType.ByteArray, value);

    public bool Contains(string key) => items.ContainsKey(key);

    public byte[]? GetBytes(string key) => items.TryGetValue(key, out var v) ? v.Value as byte[] : null;

    public ulong? GetUInt64(string key) => items.TryGetValue(key, out var v)
        ? v.Value switch
        {
            ulong u => u,
            uint u => u,
            long l and >= 0 => (ulong)l,
            int i and >= 0 => (ulong)i,
            _ => null,
        }
        : null;

    public uint? GetUInt32(string key) => GetUInt64(key) is { } v and <= uint.MaxValue ? (uint)v : null;

    public static VariantDictionary Deserialize(byte[] bytes)
    {
        var r = new ByteReader(bytes);
        var version = r.ReadUInt16();
        if ((version & 0xFF00) > (Version & 0xFF00))
            throw new KdbxFormatException("Unsupported VariantDictionary version.");

        var dict = new VariantDictionary();
        while (r.ReadByte() is var type and not 0)
        {
            var key = Encoding.UTF8.GetString(r.ReadBytes(r.ReadInt32()));
            var value = r.ReadBytes(r.ReadInt32());
            object parsed = (ValueType)type switch
            {
                ValueType.UInt32 => BinaryPrimitives.ReadUInt32LittleEndian(Check(value, 4)),
                ValueType.UInt64 => BinaryPrimitives.ReadUInt64LittleEndian(Check(value, 8)),
                ValueType.Bool => Check(value, 1)[0] != 0,
                ValueType.Int32 => BinaryPrimitives.ReadInt32LittleEndian(Check(value, 4)),
                ValueType.Int64 => BinaryPrimitives.ReadInt64LittleEndian(Check(value, 8)),
                ValueType.String => Encoding.UTF8.GetString(value),
                ValueType.ByteArray => value,
                _ => throw new KdbxFormatException($"Unknown VariantDictionary value type 0x{type:X2}."),
            };
            dict.Set(key, (ValueType)type, parsed);
        }
        return dict;
    }

    static byte[] Check(byte[] value, int length) =>
        value.Length == length ? value : throw new KdbxFormatException("Invalid VariantDictionary value size.");

    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        ms.Write(CryptoUtil.UInt32Bytes(Version).AsSpan(0, 2));
        foreach (var key in order)
        {
            var (type, raw) = items[key];
            byte[] value = raw switch
            {
                uint u => CryptoUtil.UInt32Bytes(u),
                ulong u => CryptoUtil.UInt64Bytes(u),
                bool b => [(byte)(b ? 1 : 0)],
                int i => CryptoUtil.UInt32Bytes((uint)i),
                long l => CryptoUtil.UInt64Bytes((ulong)l),
                string s => Encoding.UTF8.GetBytes(s),
                byte[] bytes => bytes,
                _ => throw new InvalidOperationException($"Unsupported VariantDictionary value {raw.GetType()}."),
            };
            var keyBytes = Encoding.UTF8.GetBytes(key);
            ms.WriteByte((byte)type);
            ms.Write(CryptoUtil.UInt32Bytes((uint)keyBytes.Length));
            ms.Write(keyBytes);
            ms.Write(CryptoUtil.UInt32Bytes((uint)value.Length));
            ms.Write(value);
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }
}

/// <summary>Well-known KDBX UUIDs (stored as raw 16-byte arrays in the file).</summary>
internal static class KdbxUuids
{
    public static readonly byte[] CipherAes256 = Convert.FromHexString("31c1f2e6bf714350be5805216afc5aff");
    public static readonly byte[] CipherChaCha20 = Convert.FromHexString("d6038a2b8b6f4cb5a524339a31dbb59a");
    public static readonly byte[] CipherTwofish = Convert.FromHexString("ad68f29f576f4bb9a36ad47af965346c");

    public static readonly byte[] KdfAes = Convert.FromHexString("c9d9f39a628a4460bf740d08c18a4fea");
    public static readonly byte[] KdfArgon2d = Convert.FromHexString("ef636ddf8c29444b91f7a9a403e30a0c");
    public static readonly byte[] KdfArgon2id = Convert.FromHexString("9e298b1956db4773b23dfc3ec6f0a1e6");

    public static bool Equal(byte[]? a, byte[] b) => a is not null && a.AsSpan().SequenceEqual(b);
}
