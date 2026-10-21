namespace PasswordPorter.KeePass.Crypto;

/// <summary>A keystream generator; <see cref="Transform"/> XORs it into data (encrypting and decrypting alike).</summary>
internal abstract class StreamCipher
{
    readonly byte[] keystream = new byte[64];
    int position = 64;

    /// <summary>Writes the next 64-byte keystream block.</summary>
    protected abstract void NextBlock(Span<byte> output);

    public void Transform(Span<byte> data)
    {
        foreach (ref var b in data)
        {
            if (position == keystream.Length)
            {
                NextBlock(keystream);
                position = 0;
            }
            b ^= keystream[position++];
        }
    }

    protected static void WriteBlock(Span<byte> output, ReadOnlySpan<uint> working, ReadOnlySpan<uint> state)
    {
        for (int i = 0; i < 16; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output[(i * 4)..], working[i] + state[i]);
    }

    protected static void ReadWords(ReadOnlySpan<byte> source, Span<uint> destination)
    {
        for (int i = 0; i < destination.Length; i++)
            destination[i] = BinaryPrimitives.ReadUInt32LittleEndian(source[(i * 4)..]);
    }
}

/// <summary>ChaCha20 as in RFC 8439 (96-bit nonce, 32-bit block counter).</summary>
internal sealed class ChaCha20 : StreamCipher
{
    readonly uint[] state = new uint[16];
    readonly uint[] x = new uint[16];

    public ChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter = 0)
    {
        if (key.Length != 32) throw new ArgumentException("ChaCha20 needs a 32-byte key.", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("ChaCha20 needs a 12-byte nonce.", nameof(nonce));
        uint[] constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
        constants.CopyTo(state, 0);
        ReadWords(key, state.AsSpan(4, 8));
        state[12] = counter;
        ReadWords(nonce, state.AsSpan(13, 3));
    }

    protected override void NextBlock(Span<byte> output)
    {
        state.CopyTo(x, 0);
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(0, 4, 8, 12); QuarterRound(1, 5, 9, 13); QuarterRound(2, 6, 10, 14); QuarterRound(3, 7, 11, 15);
            QuarterRound(0, 5, 10, 15); QuarterRound(1, 6, 11, 12); QuarterRound(2, 7, 8, 13); QuarterRound(3, 4, 9, 14);
        }
        WriteBlock(output, x, state);
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

    public Salsa20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != 32) throw new ArgumentException("Salsa20 needs a 32-byte key.", nameof(key));
        if (nonce.Length != 8) throw new ArgumentException("Salsa20 needs an 8-byte nonce.", nameof(nonce));
        (state[0], state[5], state[10], state[15]) = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574);
        ReadWords(key[..16], state.AsSpan(1, 4));
        ReadWords(key[16..], state.AsSpan(11, 4));
        ReadWords(nonce, state.AsSpan(6, 2));
        // state[8..9] is the 64-bit block counter, starting at zero.
    }

    protected override void NextBlock(Span<byte> output)
    {
        state.CopyTo(x, 0);
        for (int i = 0; i < 10; i++)
        {
            // Column round
            QuarterRound(0, 4, 8, 12); QuarterRound(5, 9, 13, 1); QuarterRound(10, 14, 2, 6); QuarterRound(15, 3, 7, 11);
            // Row round
            QuarterRound(0, 1, 2, 3); QuarterRound(5, 6, 7, 4); QuarterRound(10, 11, 8, 9); QuarterRound(15, 12, 13, 14);
        }
        WriteBlock(output, x, state);
        if (++state[8] == 0)
            state[9]++;
    }

    void QuarterRound(int a, int b, int c, int d)
    {
        x[b] ^= BitOperations.RotateLeft(x[a] + x[d], 7);
        x[c] ^= BitOperations.RotateLeft(x[b] + x[a], 9);
        x[d] ^= BitOperations.RotateLeft(x[c] + x[b], 13);
        x[a] ^= BitOperations.RotateLeft(x[d] + x[c], 18);
    }
}
