using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PasswordPorter.KeePass.Crypto;

namespace PasswordPorter.KeePass.Kdbx;

/// <summary>The file is not a valid KDBX database (corrupt, truncated or an unsupported variant).</summary>
public class KdbxFormatException : Exception
{
    public KdbxFormatException(string message) : base(message) { }
}

/// <summary>The password and/or key file do not open the database.</summary>
public sealed class KdbxInvalidKeyException : Exception
{
    public KdbxInvalidKeyException() : base("The master key is wrong (password or key file), or the file is corrupt.") { }
}

/// <summary>Bounds-checked little-endian reader over a byte array.</summary>
internal sealed class ByteReader
{
    readonly byte[] data;

    public ByteReader(byte[] data, int position = 0)
    {
        this.data = data;
        Position = position;
    }

    public int Position { get; private set; }

    public int Remaining => data.Length - Position;

    void Need(int count)
    {
        if (count < 0 || count > Remaining)
            throw new KdbxFormatException("The file is truncated or corrupt.");
    }

    public byte ReadByte()
    {
        Need(1);
        return data[Position++];
    }

    public ushort ReadUInt16()
    {
        Need(2);
        var v = (ushort)(data[Position] | (data[Position + 1] << 8));
        Position += 2;
        return v;
    }

    public uint ReadUInt32()
    {
        Need(4);
        var v = CryptoUtil.ReadUInt32(data, Position);
        Position += 4;
        return v;
    }

    public int ReadInt32() => (int)ReadUInt32();

    public byte[] ReadBytes(int count)
    {
        Need(count);
        var b = new byte[count];
        Buffer.BlockCopy(data, Position, b, 0, count);
        Position += count;
        return b;
    }
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

    const ushort Version = 0x0100;
    readonly List<string> order = new List<string>();
    readonly Dictionary<string, KeyValuePair<ValueType, object>> items = new Dictionary<string, KeyValuePair<ValueType, object>>(StringComparer.Ordinal);

    void Set(string key, ValueType type, object value)
    {
        if (!items.ContainsKey(key))
            order.Add(key);
        items[key] = new KeyValuePair<ValueType, object>(type, value);
    }

    public void SetUInt32(string key, uint value) => Set(key, ValueType.UInt32, value);
    public void SetUInt64(string key, ulong value) => Set(key, ValueType.UInt64, value);
    public void SetBytes(string key, byte[] value) => Set(key, ValueType.ByteArray, value);

    public bool Contains(string key) => items.ContainsKey(key);

    public byte[]? GetBytes(string key) => items.TryGetValue(key, out var v) ? v.Value as byte[] : null;

    public ulong? GetUInt64(string key)
    {
        if (!items.TryGetValue(key, out var v)) return null;
        switch (v.Value)
        {
            case ulong u: return u;
            case uint u: return u;
            case long l when l >= 0: return (ulong)l;
            case int i when i >= 0: return (ulong)i;
            default: return null;
        }
    }

    public uint? GetUInt32(string key)
    {
        var v = GetUInt64(key);
        return v.HasValue && v.Value <= uint.MaxValue ? (uint)v.Value : (uint?)null;
    }

    public static VariantDictionary Deserialize(byte[] bytes)
    {
        var r = new ByteReader(bytes);
        var version = r.ReadUInt16();
        if ((version & 0xFF00) > (Version & 0xFF00))
            throw new KdbxFormatException("Unsupported VariantDictionary version.");

        var dict = new VariantDictionary();
        while (true)
        {
            var type = r.ReadByte();
            if (type == 0)
                break;
            var key = Encoding.UTF8.GetString(r.ReadBytes(r.ReadInt32()));
            var value = r.ReadBytes(r.ReadInt32());
            switch ((ValueType)type)
            {
                case ValueType.UInt32: dict.Set(key, ValueType.UInt32, CryptoUtil.ReadUInt32(Check(value, 4), 0)); break;
                case ValueType.UInt64: dict.Set(key, ValueType.UInt64, CryptoUtil.ReadUInt64(Check(value, 8), 0)); break;
                case ValueType.Bool: dict.Set(key, ValueType.Bool, Check(value, 1)[0] != 0); break;
                case ValueType.Int32: dict.Set(key, ValueType.Int32, (int)CryptoUtil.ReadUInt32(Check(value, 4), 0)); break;
                case ValueType.Int64: dict.Set(key, ValueType.Int64, (long)CryptoUtil.ReadUInt64(Check(value, 8), 0)); break;
                case ValueType.String: dict.Set(key, ValueType.String, Encoding.UTF8.GetString(value)); break;
                case ValueType.ByteArray: dict.Set(key, ValueType.ByteArray, value); break;
                default: throw new KdbxFormatException($"Unknown VariantDictionary value type 0x{type:X2}.");
            }
        }
        return dict;
    }

    static byte[] Check(byte[] value, int length) =>
        value.Length == length ? value : throw new KdbxFormatException("Invalid VariantDictionary value size.");

    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        ms.WriteByte((byte)(Version & 0xFF));
        ms.WriteByte((byte)(Version >> 8));
        foreach (var key in order)
        {
            var item = items[key];
            byte[] value;
            switch (item.Key)
            {
                case ValueType.UInt32: value = CryptoUtil.UInt32Bytes((uint)item.Value); break;
                case ValueType.UInt64: value = CryptoUtil.UInt64Bytes((ulong)item.Value); break;
                case ValueType.Bool: value = new[] { (byte)((bool)item.Value ? 1 : 0) }; break;
                case ValueType.Int32: value = CryptoUtil.UInt32Bytes((uint)(int)item.Value); break;
                case ValueType.Int64: value = CryptoUtil.UInt64Bytes((ulong)(long)item.Value); break;
                case ValueType.String: value = Encoding.UTF8.GetBytes((string)item.Value); break;
                default: value = (byte[])item.Value; break;
            }
            var keyBytes = Encoding.UTF8.GetBytes(key);
            ms.WriteByte((byte)item.Key);
            ms.Write(CryptoUtil.UInt32Bytes((uint)keyBytes.Length), 0, 4);
            ms.Write(keyBytes, 0, keyBytes.Length);
            ms.Write(CryptoUtil.UInt32Bytes((uint)value.Length), 0, 4);
            ms.Write(value, 0, value.Length);
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }
}

/// <summary>Well-known KDBX UUIDs (stored as raw 16-byte arrays in the file).</summary>
internal static class KdbxUuids
{
    public static readonly byte[] CipherAes256 = CryptoUtil.FromHex("31c1f2e6bf714350be5805216afc5aff");
    public static readonly byte[] CipherChaCha20 = CryptoUtil.FromHex("d6038a2b8b6f4cb5a524339a31dbb59a");
    public static readonly byte[] CipherTwofish = CryptoUtil.FromHex("ad68f29f576f4bb9a36ad47af965346c");

    public static readonly byte[] KdfAes = CryptoUtil.FromHex("c9d9f39a628a4460bf740d08c18a4fea");
    public static readonly byte[] KdfArgon2d = CryptoUtil.FromHex("ef636ddf8c29444b91f7a9a403e30a0c");
    public static readonly byte[] KdfArgon2id = CryptoUtil.FromHex("9e298b1956db4773b23dfc3ec6f0a1e6");

    public static bool Equal(byte[]? a, byte[] b) => a != null && CryptoUtil.FixedTimeEquals(a, b);
}
