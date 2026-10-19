using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    readonly List<byte[]> components = new List<byte[]>();

    public KdbxKey(string? password, string? keyFilePath = null)
    {
        if (password != null)
            components.Add(CryptoUtil.Sha256(Encoding.UTF8.GetBytes(password)));
        if (!string.IsNullOrEmpty(keyFilePath))
            components.Add(LoadKeyFile(keyFilePath!));
        if (components.Count == 0)
            throw new ArgumentException("A master key needs a password, a key file, or both.");
    }

    /// <summary>SHA-256 over the concatenated component hashes (the input to the KDF).</summary>
    internal byte[] GetCompositeHash() => CryptoUtil.Sha256(components.ToArray());

    /// <summary>Reads a key file in any format KeePass accepts (XML v1/v2, 32 raw bytes, 64 hex chars, or any file).</summary>
    internal static byte[] LoadKeyFile(string path)
    {
        var data = File.ReadAllBytes(path);
        return TryLoadXmlKeyFile(data) ?? LoadBinaryKeyFile(data);
    }

    static byte[] LoadBinaryKeyFile(byte[] data)
    {
        if (data.Length == 32)
            return data;
        if (data.Length == 64)
        {
            var text = Encoding.ASCII.GetString(data);
            if (text.All(Uri.IsHexDigit))
                return CryptoUtil.FromHex(text);
        }
        return CryptoUtil.Sha256(data);
    }

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

        var root = doc.Root;
        if (root == null || root.Name.LocalName != "KeyFile")
            return null;
        var version = root.Element("Meta")?.Element("Version")?.Value.Trim();
        var dataElement = root.Element("Key")?.Element("Data");
        if (dataElement == null)
            return null;

        if (version != null && version.StartsWith("2."))
        {
            var hex = new string(dataElement.Value.Where(c => !char.IsWhiteSpace(c)).ToArray());
            var key = CryptoUtil.FromHex(hex);
            var expected = dataElement.Attribute("Hash")?.Value;
            if (expected != null)
            {
                var actual = CryptoUtil.Sha256(key).Take(4).ToArray();
                if (!CryptoUtil.FixedTimeEquals(actual, CryptoUtil.FromHex(expected.Trim())))
                    throw new KdbxFormatException("The key file's checksum does not match; the file is corrupt.");
            }
            return key;
        }

        // Version 1.0: base64 key data.
        return Convert.FromBase64String(dataElement.Value.Trim());
    }

    /// <summary>Writes a new random KeePass 2.0-format XML key file.</summary>
    public static void CreateKeyFile(string path)
    {
        var key = CryptoUtil.RandomBytes(32);
        var hex = CryptoUtil.ToHex(key).ToUpperInvariant();
        var grouped = string.Join(" ", Enumerable.Range(0, 8).Select(i => hex.Substring(i * 8, 8)));
        var hash = CryptoUtil.ToHex(CryptoUtil.Sha256(key).Take(4).ToArray()).ToUpperInvariant();
        var doc = new XDocument(
            new XDeclaration("1.0", "utf-8", null),
            new XElement("KeyFile",
                new XElement("Meta", new XElement("Version", "2.0")),
                new XElement("Key", new XElement("Data", new XAttribute("Hash", hash), grouped))));
        doc.Save(path);
    }
}
