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
        if (parallelism < 1 || parallelism > 0xFFFFFF) throw new ArgumentOutOfRangeException(nameof(parallelism));
        if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
        if (version != 0x10 && version != Version13) throw new ArgumentOutOfRangeException(nameof(version));
        if (tagLength < 4) throw new ArgumentOutOfRangeException(nameof(tagLength));
        secret ??= Array.Empty<byte>();
        associatedData ??= Array.Empty<byte>();

        var inst = new Instance(type, version, parallelism, memoryKiB, iterations);

        // H0 = H(p, T, m, t, v, y, |P|, P, |S|, S, |K|, K, |X|, X)
        var h0Input = Concat(
            CryptoUtil.UInt32Bytes(parallelism), CryptoUtil.UInt32Bytes((uint)tagLength),
            CryptoUtil.UInt32Bytes(memoryKiB), CryptoUtil.UInt32Bytes(iterations),
            CryptoUtil.UInt32Bytes(version), CryptoUtil.UInt32Bytes((uint)type),
            CryptoUtil.UInt32Bytes((uint)password.Length), password,
            CryptoUtil.UInt32Bytes((uint)salt.Length), salt,
            CryptoUtil.UInt32Bytes((uint)secret.Length), secret,
            CryptoUtil.UInt32Bytes((uint)associatedData.Length), associatedData);
        var h0 = Blake2b.Hash(h0Input, 64);
        Array.Clear(h0Input, 0, h0Input.Length);

        // First two blocks of each lane.
        var seed = new byte[72];
        Buffer.BlockCopy(h0, 0, seed, 0, 64);
        for (uint lane = 0; lane < parallelism; lane++)
        {
            for (uint j = 0; j < 2; j++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(64), j);
                BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(68), lane);
                var block = HPrime(seed, 1024);
                inst.LoadBlock(lane * inst.LaneLength + j, block);
            }
        }
        Array.Clear(seed, 0, seed.Length);
        Array.Clear(h0, 0, h0.Length);

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
        var final = new ulong[BlockWords];
        for (uint lane = 0; lane < parallelism; lane++)
        {
            long off = (long)(lane * inst.LaneLength + inst.LaneLength - 1) * BlockWords;
            for (int k = 0; k < BlockWords; k++)
                final[k] ^= inst.Memory[off + k];
        }
        var finalBytes = new byte[1024];
        for (int k = 0; k < BlockWords; k++)
            BinaryPrimitives.WriteUInt64LittleEndian(finalBytes.AsSpan(k * 8), final[k]);

        var tag = HPrime(finalBytes, tagLength);
        Array.Clear(inst.Memory, 0, inst.Memory.Length);
        Array.Clear(finalBytes, 0, finalBytes.Length);
        return tag;
    }

    /// <summary>The variable-length hash H' from RFC 9106 section 3.3.</summary>
    internal static byte[] HPrime(byte[] input, int outLength)
    {
        var prefixed = Concat(CryptoUtil.UInt32Bytes((uint)outLength), input);
        if (outLength <= 64)
            return Blake2b.Hash(prefixed, outLength);

        var result = new byte[outLength];
        int r = (outLength + 31) / 32 - 2;
        var v = Blake2b.Hash(prefixed, 64);
        Buffer.BlockCopy(v, 0, result, 0, 32);
        for (int i = 1; i < r; i++)
        {
            v = Blake2b.Hash(v, 64);
            Buffer.BlockCopy(v, 0, result, i * 32, 32);
        }
        var last = Blake2b.Hash(v, outLength - 32 * r);
        Buffer.BlockCopy(last, 0, result, 32 * r, last.Length);
        return result;
    }

    static byte[] Concat(params byte[][] parts)
    {
        int len = 0;
        foreach (var p in parts) len += p.Length;
        var result = new byte[len];
        int o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, result, o, p.Length);
            o += p.Length;
        }
        return result;
    }

    sealed class Instance
    {
        readonly Argon2Type type;
        readonly uint version, lanes, iterations;
        public readonly uint MemoryBlocks, LaneLength, SegmentLength;
        public readonly ulong[] Memory;

        public Instance(Argon2Type type, uint version, uint lanes, uint memoryKiB, uint iterations)
        {
            this.type = type;
            this.version = version;
            this.lanes = lanes;
            this.iterations = iterations;

            uint blocks = Math.Max(memoryKiB, 2 * SyncPoints * lanes);
            SegmentLength = blocks / (lanes * SyncPoints);
            MemoryBlocks = SegmentLength * lanes * SyncPoints;
            LaneLength = SegmentLength * SyncPoints;
            Memory = new ulong[(long)MemoryBlocks * BlockWords];
        }

        public void LoadBlock(uint index, byte[] block)
        {
            long off = (long)index * BlockWords;
            for (int k = 0; k < BlockWords; k++)
                Memory[off + k] = BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(k * 8));
        }

        public void FillSegment(uint pass, uint lane, uint slice)
        {
            var scratchR = new ulong[BlockWords];
            var scratchT = new ulong[BlockWords];

            bool dataIndependent = type == Argon2Type.Argon2i
                || (type == Argon2Type.Argon2id && pass == 0 && slice < SyncPoints / 2);

            ulong[]? addressBlock = null, inputBlock = null, zeroBlock = null;
            if (dataIndependent)
            {
                addressBlock = new ulong[BlockWords];
                inputBlock = new ulong[BlockWords];
                zeroBlock = new ulong[BlockWords];
                inputBlock[0] = pass;
                inputBlock[1] = lane;
                inputBlock[2] = slice;
                inputBlock[3] = MemoryBlocks;
                inputBlock[4] = iterations;
                inputBlock[5] = (ulong)type;
            }

            uint startIndex = 0;
            if (pass == 0 && slice == 0)
            {
                startIndex = 2;
                if (dataIndependent)
                    NextAddresses(addressBlock!, inputBlock!, zeroBlock!, scratchR, scratchT);
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
                        NextAddresses(addressBlock!, inputBlock!, zeroBlock!, scratchR, scratchT);
                    pseudoRand = addressBlock![i % BlockWords];
                }
                else
                {
                    pseudoRand = Memory[(long)prevOffset * BlockWords];
                }

                ulong refLane = (pseudoRand >> 32) % lanes;
                if (pass == 0 && slice == 0)
                    refLane = lane;

                uint refIndex = IndexAlpha(pass, slice, i, (uint)pseudoRand, refLane == lane);
                long refOffset = (long)refLane * LaneLength + refIndex;

                bool withXor = version != 0x10 && pass != 0;
                FillBlock(Memory, (long)prevOffset * BlockWords, Memory, refOffset * BlockWords,
                    Memory, (long)currOffset * BlockWords, withXor, scratchR, scratchT);
            }
        }

        uint IndexAlpha(uint pass, uint slice, uint index, uint pseudoRand, bool sameLane)
        {
            long areaSize;
            if (pass == 0)
            {
                if (slice == 0)
                    areaSize = index - 1;
                else if (sameLane)
                    areaSize = slice * SegmentLength + index - 1;
                else
                    areaSize = slice * SegmentLength + (index == 0 ? -1 : 0);
            }
            else
            {
                if (sameLane)
                    areaSize = LaneLength - SegmentLength + index - 1;
                else
                    areaSize = LaneLength - SegmentLength + (index == 0 ? -1 : 0);
            }

            ulong relative = pseudoRand;
            relative = (relative * relative) >> 32;
            relative = (ulong)areaSize - 1 - (((ulong)areaSize * relative) >> 32);

            ulong start = 0;
            if (pass != 0)
                start = slice == SyncPoints - 1 ? 0 : (ulong)(slice + 1) * SegmentLength;

            return (uint)((start + relative) % LaneLength);
        }

        static void NextAddresses(ulong[] address, ulong[] input, ulong[] zero, ulong[] r, ulong[] t)
        {
            input[6]++;
            FillBlock(zero, 0, input, 0, address, 0, false, r, t);
            FillBlock(zero, 0, address, 0, address, 0, false, r, t);
        }
    }

    /// <summary>next = G(prev, ref) (XORed into the existing next block when <paramref name="withXor"/>).</summary>
    static void FillBlock(ulong[] prevArr, long prev, ulong[] refArr, long refOff, ulong[] nextArr, long next,
        bool withXor, ulong[] r, ulong[] t)
    {
        for (int k = 0; k < BlockWords; k++)
        {
            r[k] = refArr[refOff + k] ^ prevArr[prev + k];
            t[k] = withXor ? r[k] ^ nextArr[next + k] : r[k];
        }

        // Rows: eight 16-word groups.
        for (int i = 0; i < 8; i++)
        {
            int b = 16 * i;
            P(r, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                 b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
        }

        // Columns: pairs of words at stride 16.
        for (int i = 0; i < 8; i++)
        {
            int b = 2 * i;
            P(r, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                 b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
        }

        for (int k = 0; k < BlockWords; k++)
            nextArr[next + k] = t[k] ^ r[k];
    }

    static void P(ulong[] v, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7,
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
