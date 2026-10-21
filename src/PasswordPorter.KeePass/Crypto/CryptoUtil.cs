namespace PasswordPorter.KeePass.Crypto;

/// <summary>Hashes over several buffers and small little-endian encoders, used throughout the KDBX code.</summary>
internal static class CryptoUtil
{
    public static byte[] Sha256(params ReadOnlySpan<byte[]> parts) => Hash(HashAlgorithmName.SHA256, null, parts);

    public static byte[] Sha512(params ReadOnlySpan<byte[]> parts) => Hash(HashAlgorithmName.SHA512, null, parts);

    public static byte[] HmacSha256(byte[] key, params ReadOnlySpan<byte[]> parts) => Hash(HashAlgorithmName.SHA256, key, parts);

    static byte[] Hash(HashAlgorithmName algorithm, byte[]? hmacKey, ReadOnlySpan<byte[]> parts)
    {
        using var hash = hmacKey == null ? IncrementalHash.CreateHash(algorithm) : IncrementalHash.CreateHMAC(algorithm, hmacKey);
        foreach (var part in parts)
            hash.AppendData(part);
        return hash.GetHashAndReset();
    }

    public static byte[] UInt32Bytes(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        return bytes;
    }

    public static byte[] UInt64Bytes(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
        return bytes;
    }
}
