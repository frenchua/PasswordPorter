namespace PasswordPorter.KeePass.Crypto;

internal enum Argon2Type
{
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
}

/// <summary>
/// Argon2 (RFC 9106), versions 0x10 and 0x13. A straightforward port of the reference implementation;
/// lanes within a slice are filled in parallel.
/// </summary>
internal static class Argon2
{
    const int BlockWords = 128;   // 1024-byte blocks as 64-bit words
    const int SyncPoints = 4;
    public const uint Version13 = 0x13;

    public static byte[] Hash(Argon2Type type, byte[] password, byte[] salt, uint parallelism, uint memoryKiB,
        uint iterations, uint version = Version13, int tagLength = 32, byte[]? secret = null, byte[]? associatedData = null)
    {
        ArgumentOutOfRangeException.ThrowIfZero(parallelism);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(parallelism, 0xFFFFFFu);
        ArgumentOutOfRangeException.ThrowIfZero(iterations);
        ArgumentOutOfRangeException.ThrowIfLessThan(tagLength, 4);
        if (version is not (0x10 or Version13))
            throw new ArgumentOutOfRangeException(nameof(version));
        secret ??= [];
        associatedData ??= [];

        var inst = new Instance(type, version, parallelism, memoryKiB, iterations);

        // H0 = H(p, T, m, t, v, y, |P|, P, |S|, S, |K|, K, |X|, X)
        byte[] h0Input =
        [
            .. Le(parallelism), .. Le((uint)tagLength), .. Le(memoryKiB), .. Le(iterations), .. Le(version), .. Le((uint)type),
            .. Le((uint)password.Length), .. password,
            .. Le((uint)salt.Length), .. salt,
            .. Le((uint)secret.Length), .. secret,
            .. Le((uint)associatedData.Length), .. associatedData,
        ];
        var h0 = Blake2b.Hash(h0Input, 64);
        CryptographicOperations.ZeroMemory(h0Input);

        // First two blocks of each lane: H'(1024, H0 || j || lane).
        var seed = new byte[72];
        h0.CopyTo(seed, 0);
        for (uint lane = 0; lane < parallelism; lane++)
        {
            for (uint j = 0; j < 2; j++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(64), j);
                BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(68), lane);
                inst.LoadBlock(lane * inst.LaneLength + j, HPrime(seed, 1024));
            }
        }
        CryptographicOperations.ZeroMemory(seed);
        CryptographicOperations.ZeroMemory(h0);

        for (uint pass = 0; pass < iterations; pass++)
        {
            for (uint slice = 0; slice < SyncPoints; slice++)
            {
                uint p = pass, s = slice;
                if (parallelism == 1)
                    inst.FillSegment(p, 0, s);
                else
                    Parallel.For(0, (int)parallelism, lane => inst.FillSegment(p, (uint)lane, s));
            }
        }

        // Final block: XOR of the last block of every lane.
        Span<ulong> final = stackalloc ulong[BlockWords];
        for (uint lane = 0; lane < parallelism; lane++)
        {
            var last = inst.Block(lane * inst.LaneLength + inst.LaneLength - 1);
            for (int k = 0; k < BlockWords; k++)
                final[k] ^= last[k];
        }
        var finalBytes = new byte[1024];
        for (int k = 0; k < BlockWords; k++)
            BinaryPrimitives.WriteUInt64LittleEndian(finalBytes.AsSpan(k * 8), final[k]);

        var tag = HPrime(finalBytes, tagLength);
        Array.Clear(inst.Memory);
        CryptographicOperations.ZeroMemory(finalBytes);
        return tag;
    }

    static byte[] Le(uint value) => CryptoUtil.UInt32Bytes(value);

    /// <summary>The variable-length hash H' from RFC 9106 section 3.3.</summary>
    internal static byte[] HPrime(ReadOnlySpan<byte> input, int outLength)
    {
        byte[] prefixed = [.. Le((uint)outLength), .. input];
        if (outLength <= 64)
            return Blake2b.Hash(prefixed, outLength);

        var result = new byte[outLength];
        int r = (outLength + 31) / 32 - 2;
        var v = Blake2b.Hash(prefixed, 64);
        v.AsSpan(0, 32).CopyTo(result);
        for (int i = 1; i < r; i++)
        {
            v = Blake2b.Hash(v, 64);
            v.AsSpan(0, 32).CopyTo(result.AsSpan(i * 32));
        }
        Blake2b.Hash(v, outLength - 32 * r).CopyTo(result.AsSpan(32 * r));
        return result;
    }

    sealed class Instance(Argon2Type type, uint version, uint lanes, uint memoryKiB, uint iterations)
    {
        public readonly uint SegmentLength = Math.Max(memoryKiB, 2 * SyncPoints * lanes) / (lanes * SyncPoints);
        public uint LaneLength => SegmentLength * SyncPoints;
        uint MemoryBlocks => LaneLength * lanes;

        public readonly ulong[] Memory =
            new ulong[(long)(Math.Max(memoryKiB, 2 * SyncPoints * lanes) / (lanes * SyncPoints)) * SyncPoints * lanes * BlockWords];

        public Span<ulong> Block(long index) => Memory.AsSpan((int)(index * BlockWords), BlockWords);

        public void LoadBlock(uint index, byte[] block)
        {
            var target = Block(index);
            for (int k = 0; k < BlockWords; k++)
                target[k] = BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(k * 8));
        }

        public void FillSegment(uint pass, uint lane, uint slice)
        {
            Span<ulong> r = stackalloc ulong[BlockWords];
            Span<ulong> t = stackalloc ulong[BlockWords];

            bool dataIndependent = type == Argon2Type.Argon2i
                || (type == Argon2Type.Argon2id && pass == 0 && slice < SyncPoints / 2);

            // Only used for data-independent addressing.
            Span<ulong> address = stackalloc ulong[BlockWords];
            Span<ulong> input = stackalloc ulong[BlockWords];
            Span<ulong> zero = stackalloc ulong[BlockWords];
            if (dataIndependent)
            {
                input[0] = pass;
                input[1] = lane;
                input[2] = slice;
                input[3] = MemoryBlocks;
                input[4] = iterations;
                input[5] = (ulong)type;
            }

            uint startIndex = 0;
            if (pass == 0 && slice == 0)
            {
                startIndex = 2;
                if (dataIndependent)
                    NextAddresses(address, input, zero, r, t);
            }

            uint currOffset = lane * LaneLength + slice * SegmentLength + startIndex;
            uint prevOffset = currOffset % LaneLength == 0 ? currOffset + LaneLength - 1 : currOffset - 1;

            for (uint i = startIndex; i < SegmentLength; i++, currOffset++, prevOffset++)
            {
                if (currOffset % LaneLength == 1)
                    prevOffset = currOffset - 1;

                ulong pseudoRand;
                if (dataIndependent)
                {
                    if (i % BlockWords == 0)
                        NextAddresses(address, input, zero, r, t);
                    pseudoRand = address[(int)(i % BlockWords)];
                }
                else
                {
                    pseudoRand = Block(prevOffset)[0];
                }

                ulong refLane = pass == 0 && slice == 0 ? lane : (pseudoRand >> 32) % lanes;
                uint refIndex = IndexAlpha(pass, slice, i, (uint)pseudoRand, refLane == lane);

                bool withXor = version != 0x10 && pass != 0;
                FillBlock(Block(prevOffset), Block((long)refLane * LaneLength + refIndex), Block(currOffset), withXor, r, t);
            }
        }

        uint IndexAlpha(uint pass, uint slice, uint index, uint pseudoRand, bool sameLane)
        {
            long areaSize = (pass, slice, sameLane) switch
            {
                (0, 0, _) => index - 1,
                (0, _, true) => slice * SegmentLength + index - 1,
                (0, _, false) => slice * SegmentLength + (index == 0 ? -1 : 0),
                (_, _, true) => LaneLength - SegmentLength + index - 1,
                _ => LaneLength - SegmentLength + (index == 0 ? -1 : 0),
            };

            ulong relative = pseudoRand;
            relative = (relative * relative) >> 32;
            relative = (ulong)areaSize - 1 - (((ulong)areaSize * relative) >> 32);

            ulong start = pass == 0 || slice == SyncPoints - 1 ? 0 : (ulong)(slice + 1) * SegmentLength;
            return (uint)((start + relative) % LaneLength);
        }

        static void NextAddresses(Span<ulong> address, Span<ulong> input, Span<ulong> zero, Span<ulong> r, Span<ulong> t)
        {
            input[6]++;
            FillBlock(zero, input, address, false, r, t);
            FillBlock(zero, address, address, false, r, t);
        }
    }

    /// <summary>next = G(prev, ref) (XORed into the existing next block when <paramref name="withXor"/>).</summary>
    static void FillBlock(ReadOnlySpan<ulong> prev, ReadOnlySpan<ulong> refBlock, Span<ulong> next,
        bool withXor, Span<ulong> r, Span<ulong> t)
    {
        for (int k = 0; k < BlockWords; k++)
        {
            r[k] = refBlock[k] ^ prev[k];
            t[k] = withXor ? r[k] ^ next[k] : r[k];
        }

        // Rows: eight 16-word groups.
        for (int b = 0; b < BlockWords; b += 16)
        {
            P(r, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                 b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
        }

        // Columns: pairs of words at stride 16.
        for (int b = 0; b < 16; b += 2)
        {
            P(r, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                 b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
        }

        for (int k = 0; k < BlockWords; k++)
            next[k] = t[k] ^ r[k];
    }

    static void P(Span<ulong> v, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7,
        int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15)
    {
        GB(ref v[v0], ref v[v4], ref v[v8], ref v[v12]);
        GB(ref v[v1], ref v[v5], ref v[v9], ref v[v13]);
        GB(ref v[v2], ref v[v6], ref v[v10], ref v[v14]);
        GB(ref v[v3], ref v[v7], ref v[v11], ref v[v15]);
        GB(ref v[v0], ref v[v5], ref v[v10], ref v[v15]);
        GB(ref v[v1], ref v[v6], ref v[v11], ref v[v12]);
        GB(ref v[v2], ref v[v7], ref v[v8], ref v[v13]);
        GB(ref v[v3], ref v[v4], ref v[v9], ref v[v14]);
    }

    static void GB(ref ulong a, ref ulong b, ref ulong c, ref ulong d)
    {
        a = a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
        d = BitOperations.RotateRight(d ^ a, 32);
        c = c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF);
        b = BitOperations.RotateRight(b ^ c, 24);
        a = a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
        d = BitOperations.RotateRight(d ^ a, 16);
        c = c + d + 2 * (c & 0xFFFFFFFF) * (d & 0xFFFFFFFF);
        b = BitOperations.RotateRight(b ^ c, 63);
    }
}
