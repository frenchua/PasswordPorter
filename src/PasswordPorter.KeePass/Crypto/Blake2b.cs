using System;

namespace PasswordPorter.KeePass.Crypto;

/// <summary>Unkeyed BLAKE2b (RFC 7693) with 1..64 byte output, as needed by Argon2.</summary>
internal static class Blake2b
{
    static readonly ulong[] IV =
    {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
    };

    static readonly byte[,] Sigma =
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    };

    public static byte[] Hash(byte[] data, int outLength) => Hash(data, 0, data.Length, outLength);

    public static byte[] Hash(byte[] data, int offset, int count, int outLength)
    {
        if (outLength < 1 || outLength > 64)
            throw new ArgumentOutOfRangeException(nameof(outLength));

        var h = (ulong[])IV.Clone();
        h[0] ^= 0x01010000UL ^ (ulong)outLength;

        var m = new ulong[16];
        var v = new ulong[16];
        var block = new byte[128];
        ulong t = 0;
        int remaining = count, pos = offset;

        // All blocks except the last are compressed without the final flag.
        while (remaining > 128)
        {
            t += 128;
            Compress(h, data, pos, t, false, m, v);
            pos += 128;
            remaining -= 128;
        }

        Array.Clear(block, 0, 128);
        Buffer.BlockCopy(data, pos, block, 0, remaining);
        t += (ulong)remaining;
        Compress(h, block, 0, t, true, m, v);

        var full = new byte[64];
        for (int i = 0; i < 8; i++)
            CryptoUtil.WriteUInt64(full, i * 8, h[i]);
        if (outLength == 64)
            return full;
        var result = new byte[outLength];
        Buffer.BlockCopy(full, 0, result, 0, outLength);
        return result;
    }

    static void Compress(ulong[] h, byte[] block, int offset, ulong t, bool last, ulong[] m, ulong[] v)
    {
        for (int i = 0; i < 16; i++)
            m[i] = CryptoUtil.ReadUInt64(block, offset + i * 8);
        for (int i = 0; i < 8; i++)
        {
            v[i] = h[i];
            v[i + 8] = IV[i];
        }
        v[12] ^= t;              // low 64 bits of the counter; inputs here never exceed 2^64 bytes
        if (last)
            v[14] = ~v[14];

        for (int r = 0; r < 12; r++)
        {
            int s = r % 10;
            G(v, 0, 4, 8, 12, m[Sigma[s, 0]], m[Sigma[s, 1]]);
            G(v, 1, 5, 9, 13, m[Sigma[s, 2]], m[Sigma[s, 3]]);
            G(v, 2, 6, 10, 14, m[Sigma[s, 4]], m[Sigma[s, 5]]);
            G(v, 3, 7, 11, 15, m[Sigma[s, 6]], m[Sigma[s, 7]]);
            G(v, 0, 5, 10, 15, m[Sigma[s, 8]], m[Sigma[s, 9]]);
            G(v, 1, 6, 11, 12, m[Sigma[s, 10]], m[Sigma[s, 11]]);
            G(v, 2, 7, 8, 13, m[Sigma[s, 12]], m[Sigma[s, 13]]);
            G(v, 3, 4, 9, 14, m[Sigma[s, 14]], m[Sigma[s, 15]]);
        }

        for (int i = 0; i < 8; i++)
            h[i] ^= v[i] ^ v[i + 8];
    }

    static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = RotR(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = RotR(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = RotR(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = RotR(v[b] ^ v[c], 63);
    }

    static ulong RotR(ulong x, int n) => (x >> n) | (x << (64 - n));
}
