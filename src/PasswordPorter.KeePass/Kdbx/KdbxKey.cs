using System.Text;
using System.Xml;
using System.Xml.Linq;
using PasswordPorter.KeePass.Crypto;

namespace PasswordPorter.KeePass.Kdbx;

/// <summary>
/// A KeePass composite master key: a password, a key file, or both.
/// (Windows user account keys are not supported.)
/// </summary>
public sealed class KdbxKey
{
    readonly List<byte[]> components = [];

    public KdbxKey(string? password, string? keyFilePath = null)
    {
        if (password is not null)
            components.Add(CryptoUtil.Sha256(Encoding.UTF8.GetBytes(password)));
        if (!string.IsNullOrEmpty(keyFilePath))
            components.Add(LoadKeyFile(keyFilePath));
        if (components is [])
            throw new ArgumentException("A master key needs a password, a key file, or both.");
    }

    /// <summary>SHA-256 over the concatenated component hashes (the input to the KDF).</summary>
    internal byte[] GetCompositeHash() => CryptoUtil.Sha256([.. components]);

    /// <summary>Reads a key file in any format KeePass accepts (XML v1/v2, 32 raw bytes, 64 hex chars, or any file).</summary>
    internal static byte[] LoadKeyFile(string path)
    {
        var data = File.ReadAllBytes(path);
        return TryLoadXmlKeyFile(data) ?? LoadBinaryKeyFile(data);
    }

    static byte[] LoadBinaryKeyFile(byte[] data) => data switch
    {
        { Length: 32 } => data,
        { Length: 64 } when Encoding.ASCII.GetString(data) is var text && text.All(char.IsAsciiHexDigit) => Convert.FromHexString(text),
        _ => CryptoUtil.Sha256(data),
    };

    static byte[]? TryLoadXmlKeyFile(byte[] data)
    {
        XDocument doc;
        try
        {
            using var ms = new MemoryStream(data);
            doc = XDocument.Load(ms);
        }
        catch (XmlException)
        {
            return null;
        }

        if (doc.Root is not { Name.LocalName: "KeyFile" } root || root.Element("Key")?.Element("Data") is not { } dataElement)
            return null;

        if (root.Element("Meta")?.Element("Version")?.Value.Trim() is { } version && version.StartsWith("2."))
        {
            var key = Convert.FromHexString(string.Concat(dataElement.Value.Where(c => !char.IsWhiteSpace(c))));
            if (dataElement.Attribute("Hash")?.Value is { } expected
                && !CryptographicOperations.FixedTimeEquals(CryptoUtil.Sha256(key).AsSpan(0, 4), Convert.FromHexString(expected.Trim())))
                throw new KdbxFormatException("The key file's checksum does not match; the file is corrupt.");
            return key;
        }

        // Version 1.0: base64 key data.
        return Convert.FromBase64String(dataElement.Value.Trim());
    }

    /// <summary>Writes a new random KeePass 2.0-format XML key file.</summary>
    public static void CreateKeyFile(string path)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var grouped = string.Join(" ", Convert.ToHexString(key).Chunk(8).Select(chunk => new string(chunk)));
        var hash = Convert.ToHexString(CryptoUtil.Sha256(key), 0, 4);
        new XDocument(
            new XDeclaration("1.0", "utf-8", null),
            new XElement("KeyFile",
                new XElement("Meta", new XElement("Version", "2.0")),
                new XElement("Key", new XElement("Data", new XAttribute("Hash", hash), grouped))))
            .Save(path);
    }
}
