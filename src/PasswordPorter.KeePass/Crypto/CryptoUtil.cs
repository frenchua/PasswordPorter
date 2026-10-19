using System;
using System.Security.Cryptography;

namespace PasswordPorter.KeePass.Crypto;

/// <summary>Hashing, randomness and little-endian helpers that work the same on .NET Framework and modern .NET.</summary>
internal static class CryptoUtil
{
    static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    public static byte[] Sha256(params byte[][] parts)
    {
        using var h = SHA256.Create();
        return Hash(h, parts);
    }

    public static byte[] Sha512(params byte[][] parts)
    {
        using var h = SHA512.Create();
        return Hash(h, parts);
    }

    static byte[] Hash(HashAlgorithm h, byte[][] parts)
    {
        foreach (var p in parts)
            h.TransformBlock(p, 0, p.Length, null, 0);
        h.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return h.Hash!;
    }

    public static byte[] HmacSha256(byte[] key, params byte[][] parts)
    {
        using var h = new HMACSHA256(key);
        return Hash(h, parts);
    }

    public static byte[] RandomBytes(int count)
    {
        var b = new byte[count];
        lock (Rng)
            Rng.GetBytes(b);
        return b;
    }

    public static bool FixedTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    public static bool StartsWith(byte[] data, int offset, byte[] prefix)
    {
        if (data.Length - offset < prefix.Length)
            return false;
        for (int i = 0; i < prefix.Length; i++)
            if (data[offset + i] != prefix[i]) return false;
        return true;
    }

    public static uint ReadUInt32(byte[] b, int o) =>
        (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

    public static ulong ReadUInt64(byte[] b, int o) =>
        ReadUInt32(b, o) | ((ulong)ReadUInt32(b, o + 4) << 32);

    public static void WriteUInt32(byte[] b, int o, uint v)
    {
        b[o] = (byte)v;
        b[o + 1] = (byte)(v >> 8);
        b[o + 2] = (byte)(v >> 16);
        b[o + 3] = (byte)(v >> 24);
    }

    public static void WriteUInt64(byte[] b, int o, ulong v)
    {
        WriteUInt32(b, o, (uint)v);
        WriteUInt32(b, o + 4, (uint)(v >> 32));
    }

    public static byte[] UInt32Bytes(uint v)
    {
        var b = new byte[4];
        WriteUInt32(b, 0, v);
        return b;
    }

    public static byte[] UInt64Bytes(ulong v)
    {
        var b = new byte[8];
        WriteUInt64(b, 0, v);
        return b;
    }

    public static byte[] FromHex(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new FormatException("Hex string has an odd length.");
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    public static string ToHex(byte[] data)
    {
        var c = new char[data.Length * 2];
        const string digits = "0123456789abcdef";
        for (int i = 0; i < data.Length; i++)
        {
            c[i * 2] = digits[data[i] >> 4];
            c[i * 2 + 1] = digits[data[i] & 0xF];
        }
        return new string(c);
    }
}
