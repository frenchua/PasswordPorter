namespace PasswordPorter.KeePass.Crypto;

/// <summary>A keystream generator; <see cref="Transform"/> XORs it into data (encrypting and decrypting alike).</summary>
internal abstract class StreamCipher
{
    readonly byte[] keystream = new byte[64];
    int position = 64;

    protected abstract void NextBlock(byte[] output);

    public void Transform(byte[] data) => Transform(data, 0, data.Length);

    public void Transform(byte[] data, int offset, int count)
    {
        for (int i = 0; i < count; i++)
        {
            if (position == 64)
            {
                NextBlock(keystream);
                position = 0;
            }
            data[offset + i] ^= keystream[position++];
        }
    }
}

/// <summary>ChaCha20 as in RFC 8439 (96-bit nonce, 32-bit block counter).</summary>
internal sealed class ChaCha20 : StreamCipher
{
    readonly uint[] state = new uint[16];
    readonly uint[] x = new uint[16];

    public ChaCha20(byte[] key, byte[] nonce, uint counter = 0)
    {
        if (key.Length != 32) throw new ArgumentException("ChaCha20 needs a 32-byte key.", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("ChaCha20 needs a 12-byte nonce.", nameof(nonce));
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++)
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4));
        state[12] = counter;
        for (int i = 0; i < 3; i++)
            state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(i * 4));
    }

    protected override void NextBlock(byte[] output)
    {
        Array.Copy(state, x, 16);
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(0, 4, 8, 12); QuarterRound(1, 5, 9, 13); QuarterRound(2, 6, 10, 14); QuarterRound(3, 7, 11, 15);
            QuarterRound(0, 5, 10, 15); QuarterRound(1, 6, 11, 12); QuarterRound(2, 7, 8, 13); QuarterRound(3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4), x[i] + state[i]);
        state[12]++;
    }

    void QuarterRound(int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }
}

/// <summary>Salsa20/20 with a 256-bit key and 64-bit nonce (KDBX 3.x inner stream).</summary>
internal sealed class Salsa20 : StreamCipher
{
    readonly uint[] state = new uint[16];
    readonly uint[] x = new uint[16];

    public Salsa20(byte[] key, byte[] nonce)
    {
        if (key.Length != 32) throw new ArgumentException("Salsa20 needs a 32-byte key.", nameof(key));
        if (nonce.Length != 8) throw new ArgumentException("Salsa20 needs an 8-byte nonce.", nameof(nonce));
        state[0] = 0x61707865; state[5] = 0x3320646e; state[10] = 0x79622d32; state[15] = 0x6b206574;
        for (int i = 0; i < 4; i++)
        {
            state[1 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4));
            state[11 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(16 + i * 4));
        }
        state[6] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(0));
        state[7] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(4));
        state[8] = 0;
        state[9] = 0;
    }

    protected override void NextBlock(byte[] output)
    {
        Array.Copy(state, x, 16);
        for (int i = 0; i < 10; i++)
        {
            // Column round
            x[4] ^= BitOperations.RotateLeft(x[0] + x[12], 7); x[8] ^= BitOperations.RotateLeft(x[4] + x[0], 9); x[12] ^= BitOperations.RotateLeft(x[8] + x[4], 13); x[0] ^= BitOperations.RotateLeft(x[12] + x[8], 18);
            x[9] ^= BitOperations.RotateLeft(x[5] + x[1], 7); x[13] ^= BitOperations.RotateLeft(x[9] + x[5], 9); x[1] ^= BitOperations.RotateLeft(x[13] + x[9], 13); x[5] ^= BitOperations.RotateLeft(x[1] + x[13], 18);
            x[14] ^= BitOperations.RotateLeft(x[10] + x[6], 7); x[2] ^= BitOperations.RotateLeft(x[14] + x[10], 9); x[6] ^= BitOperations.RotateLeft(x[2] + x[14], 13); x[10] ^= BitOperations.RotateLeft(x[6] + x[2], 18);
            x[3] ^= BitOperations.RotateLeft(x[15] + x[11], 7); x[7] ^= BitOperations.RotateLeft(x[3] + x[15], 9); x[11] ^= BitOperations.RotateLeft(x[7] + x[3], 13); x[15] ^= BitOperations.RotateLeft(x[11] + x[7], 18);
            // Row round
            x[1] ^= BitOperations.RotateLeft(x[0] + x[3], 7); x[2] ^= BitOperations.RotateLeft(x[1] + x[0], 9); x[3] ^= BitOperations.RotateLeft(x[2] + x[1], 13); x[0] ^= BitOperations.RotateLeft(x[3] + x[2], 18);
            x[6] ^= BitOperations.RotateLeft(x[5] + x[4], 7); x[7] ^= BitOperations.RotateLeft(x[6] + x[5], 9); x[4] ^= BitOperations.RotateLeft(x[7] + x[6], 13); x[5] ^= BitOperations.RotateLeft(x[4] + x[7], 18);
            x[11] ^= BitOperations.RotateLeft(x[10] + x[9], 7); x[8] ^= BitOperations.RotateLeft(x[11] + x[10], 9); x[9] ^= BitOperations.RotateLeft(x[8] + x[11], 13); x[10] ^= BitOperations.RotateLeft(x[9] + x[8], 18);
            x[12] ^= BitOperations.RotateLeft(x[15] + x[14], 7); x[13] ^= BitOperations.RotateLeft(x[12] + x[15], 9); x[14] ^= BitOperations.RotateLeft(x[13] + x[12], 13); x[15] ^= BitOperations.RotateLeft(x[14] + x[13], 18);
        }
        for (int i = 0; i < 16; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4), x[i] + state[i]);
        if (++state[8] == 0)
            state[9]++;
    }
}
