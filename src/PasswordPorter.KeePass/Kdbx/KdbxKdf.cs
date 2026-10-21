using PasswordPorter.KeePass.Crypto;

namespace PasswordPorter.KeePass.Kdbx;

public enum KdbxKdfAlgorithm
{
    Argon2id,
    Argon2d,
    AesKdf,
}

/// <summary>Key-derivation settings for a newly created database.</summary>
public sealed class KdbxKdfSettings
{
    public KdbxKdfAlgorithm Algorithm { get; set; } = KdbxKdfAlgorithm.Argon2id;

    /// <summary>Argon2 memory in bytes. Default 64 MiB.</summary>
    public ulong MemoryBytes { get; set; } = 64UL * 1024 * 1024;

    /// <summary>Argon2 passes, or AES-KDF rounds.</summary>
    public ulong Iterations { get; set; } = 10;

    public uint Parallelism { get; set; } = 2;

    internal VariantDictionary ToParameters()
    {
        var p = new VariantDictionary();
        if (Algorithm == KdbxKdfAlgorithm.AesKdf)
        {
            p.SetBytes("$UUID", KdbxUuids.KdfAes);
            p.SetUInt64("R", Iterations);
            p.SetBytes("S", RandomNumberGenerator.GetBytes(32));
            return p;
        }

        p.SetBytes("$UUID", Algorithm == KdbxKdfAlgorithm.Argon2d ? KdbxUuids.KdfArgon2d : KdbxUuids.KdfArgon2id);
        p.SetBytes("S", RandomNumberGenerator.GetBytes(32));
        p.SetUInt32("P", Parallelism);
        p.SetUInt64("M", MemoryBytes);
        p.SetUInt64("I", Iterations);
        p.SetUInt32("V", Argon2.Version13);
        return p;
    }
}

/// <summary>Runs the KDF described by a KDBX KDF parameter dictionary.</summary>
internal static class KdbxKdf
{
    public static byte[] Transform(VariantDictionary p, byte[] compositeKey)
    {
        var uuid = p.GetBytes("$UUID");
        if (KdbxUuids.Equal(uuid, KdbxUuids.KdfAes))
        {
            var seed = p.GetBytes("S") ?? throw new KdbxFormatException("AES-KDF seed missing.");
            var rounds = p.GetUInt64("R") ?? throw new KdbxFormatException("AES-KDF rounds missing.");
            return AesKdf(compositeKey, seed, rounds);
        }

        var type = KdbxUuids.Equal(uuid, KdbxUuids.KdfArgon2d) ? Argon2Type.Argon2d
            : KdbxUuids.Equal(uuid, KdbxUuids.KdfArgon2id) ? Argon2Type.Argon2id
            : throw new KdbxFormatException("Unsupported key derivation function.");

        var salt = p.GetBytes("S") ?? throw new KdbxFormatException("Argon2 salt missing.");
        var parallelism = p.GetUInt32("P") ?? throw new KdbxFormatException("Argon2 parallelism missing.");
        var memory = p.GetUInt64("M") ?? throw new KdbxFormatException("Argon2 memory missing.");
        var iterations = p.GetUInt64("I") ?? throw new KdbxFormatException("Argon2 iterations missing.");
        var version = p.GetUInt32("V") ?? Argon2.Version13;
        if (memory / 1024 > uint.MaxValue || iterations > uint.MaxValue)
            throw new KdbxFormatException("Argon2 parameters out of range.");

        return Argon2.Hash(type, compositeKey, salt, parallelism, (uint)(memory / 1024), (uint)iterations, version, 32,
            p.GetBytes("K"), p.GetBytes("A"));
    }

    /// <summary>Gives the parameters fresh random salt/seed, as KeePass does on every save.</summary>
    public static void Reseed(VariantDictionary p) =>
        p.SetBytes("S", RandomNumberGenerator.GetBytes(p.GetBytes("S") is { Length: > 0 } current ? current.Length : 32));

    static byte[] AesKdf(byte[] key, byte[] seed, ulong rounds)
    {
        using var aes = Aes.Create();
        aes.Key = seed;

        var a = (byte[])key.Clone();
        var b = new byte[32];
        for (ulong i = 0; i < rounds; i++)
        {
            aes.EncryptEcb(a, b, PaddingMode.None);
            (a, b) = (b, a);
        }
        var result = CryptoUtil.Sha256(a);
        CryptographicOperations.ZeroMemory(a);
        CryptographicOperations.ZeroMemory(b);
        return result;
    }
}
