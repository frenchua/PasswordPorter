using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using PasswordPorter.KeePass.Crypto;

namespace PasswordPorter.KeePass.Kdbx;

/// <summary>
/// A KeePass database file. Reads KDBX 3.1 and 4.x; saves in the version it was loaded with
/// (new databases are KDBX 4.0).
/// <para>
/// The decrypted XML is kept as-is in <see cref="Document"/>, so everything this library does not
/// model (history, attachments, icons, plugin data...) survives a load/save cycle untouched.
/// Protected values are held as plain text in the document while loaded and re-protected on save.
/// </para>
/// </summary>
public sealed class KdbxDatabase
{
    const uint Signature1 = 0x9AA2D903;
    const uint Signature2 = 0xB54BFB67;
    const uint Signature2Kdb = 0xB54BFB65;
    internal const uint FileVersion31 = 0x00030001;
    internal const uint FileVersion40 = 0x00040000;
    const int BlockSize = 1024 * 1024;

    static readonly byte[] EndOfHeader = { 0x0D, 0x0A, 0x0D, 0x0A };
    static readonly byte[] Salsa20Nonce = { 0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A };
    const uint InnerStreamSalsa20 = 2;
    const uint InnerStreamChaCha20 = 3;

    byte[] cipherId = KdbxUuids.CipherAes256;
    bool compressed = true;
    VariantDictionary kdfParameters = new KdbxKdfSettings().ToParameters();
    byte[]? publicCustomData;
    readonly List<Binary> binaries = new List<Binary>();

    KdbxDatabase(XDocument document, uint fileVersion)
    {
        Document = document;
        FileVersion = fileVersion;
    }

    /// <summary>Format version, e.g. 0x00040000 for KDBX 4.0.</summary>
    public uint FileVersion { get; }

    public string FileVersionText => $"{FileVersion >> 16}.{FileVersion & 0xFFFF}";

    bool IsKdbx4 => FileVersion >> 16 >= 4;

    /// <summary>The decrypted database XML (protected values in plain text).</summary>
    public XDocument Document { get; }

    XElement Meta => Document.Root?.Element("Meta") ?? throw new KdbxFormatException("The database XML has no Meta element.");

    public KdbxGroup RootGroup =>
        new KdbxGroup(this, Document.Root?.Element("Root")?.Element("Group") ?? throw new KdbxFormatException("The database has no root group."));

    public string? RecycleBinUuid
    {
        get
        {
            var enabled = Meta.Element("RecycleBinEnabled")?.Value;
            var uuid = Meta.Element("RecycleBinUUID")?.Value;
            if (string.Equals(enabled, "False", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(uuid) || uuid == KdbxGroup.ZeroUuid)
                return null;
            return uuid;
        }
    }

    // ---------------------------------------------------------------- creation

    public static KdbxDatabase Create(string name, KdbxKdfSettings? kdf = null) => Create(name, kdf, FileVersion40);

    /// <summary>Creates a database in a specific format version (KDBX 3.1 requires AES-KDF). Used by tests.</summary>
    internal static KdbxDatabase Create(string name, KdbxKdfSettings? kdf, uint fileVersion)
    {
        var now = DateTime.UtcNow;
        var db = new KdbxDatabase(new XDocument(new XDeclaration("1.0", "utf-8", "yes")), fileVersion);
        db.kdfParameters = (kdf ?? new KdbxKdfSettings()).ToParameters();

        string T(DateTime t) => db.FormatTime(t);
        var zero = KdbxGroup.ZeroUuid;
        db.Document.Add(new XElement("KeePassFile",
            new XElement("Meta",
                new XElement("Generator", "PasswordPorter"),
                new XElement("DatabaseName", name),
                new XElement("DatabaseNameChanged", T(now)),
                new XElement("DatabaseDescription"),
                new XElement("DatabaseDescriptionChanged", T(now)),
                new XElement("DefaultUserName"),
                new XElement("DefaultUserNameChanged", T(now)),
                new XElement("MaintenanceHistoryDays", 365),
                new XElement("Color"),
                new XElement("MasterKeyChanged", T(now)),
                new XElement("MasterKeyChangeRec", -1),
                new XElement("MasterKeyChangeForce", -1),
                new XElement("MemoryProtection",
                    new XElement("ProtectTitle", "False"),
                    new XElement("ProtectUserName", "False"),
                    new XElement("ProtectPassword", "True"),
                    new XElement("ProtectURL", "False"),
                    new XElement("ProtectNotes", "False")),
                new XElement("RecycleBinEnabled", "True"),
                new XElement("RecycleBinUUID", zero),
                new XElement("RecycleBinChanged", T(now)),
                new XElement("EntryTemplatesGroup", zero),
                new XElement("EntryTemplatesGroupChanged", T(now)),
                new XElement("HistoryMaxItems", 10),
                new XElement("HistoryMaxSize", 6291456),
                new XElement("LastSelectedGroup", zero),
                new XElement("LastTopVisibleGroup", zero)),
            new XElement("Root",
                KdbxGroup.CreateElement(db, name, iconId: 49),
                new XElement("DeletedObjects"))));
        return db;
    }

    // ---------------------------------------------------------------- loading

    public static KdbxDatabase Load(string path, KdbxKey key) => Load(File.ReadAllBytes(path), key);

    public static KdbxDatabase Load(byte[] file, KdbxKey key)
    {
        var r = new ByteReader(file);
        var sig1 = r.ReadUInt32();
        var sig2 = r.ReadUInt32();
        if (sig1 == Signature1 && sig2 == Signature2Kdb)
            throw new KdbxFormatException("This is a KeePass 1.x (.kdb) database, which is not supported. Open it in KeePass 2 and save it as .kdbx.");
        if (sig1 != Signature1 || sig2 != Signature2)
            throw new KdbxFormatException("Not a KeePass database.");

        var version = r.ReadUInt32();
        switch (version >> 16)
        {
            case 3: return Load3(file, r, version, key);
            case 4: return Load4(file, r, version, key);
            default: throw new KdbxFormatException($"Unsupported KDBX version {version >> 16}.{version & 0xFFFF}.");
        }
    }

    static KdbxDatabase Load4(byte[] file, ByteReader r, uint version, KdbxKey key)
    {
        byte[]? cipherId = null, masterSeed = null, iv = null, publicCustomData = null;
        uint compression = 0;
        VariantDictionary? kdf = null;

        while (true)
        {
            var id = r.ReadByte();
            var data = r.ReadBytes(r.ReadInt32());
            if (id == 0) break;
            switch (id)
            {
                case 2: cipherId = data; break;
                case 3: compression = CryptoUtil.ReadUInt32(data, 0); break;
                case 4: masterSeed = data; break;
                case 7: iv = data; break;
                case 11: kdf = VariantDictionary.Deserialize(data); break;
                case 12: publicCustomData = data; break;
            }
        }
        int headerLength = r.Position;
        if (cipherId == null || masterSeed == null || iv == null || kdf == null)
            throw new KdbxFormatException("The database header is incomplete.");

        var header = new byte[headerLength];
        Buffer.BlockCopy(file, 0, header, 0, headerLength);
        if (!CryptoUtil.FixedTimeEquals(r.ReadBytes(32), CryptoUtil.Sha256(header)))
            throw new KdbxFormatException("The database header is corrupt (checksum mismatch).");
        var headerHmac = r.ReadBytes(32);

        var transformed = KdbxKdf.Transform(kdf, key.GetCompositeHash());
        var cipherKey = CryptoUtil.Sha256(masterSeed, transformed);
        var hmacKey = CryptoUtil.Sha512(masterSeed, transformed, new byte[] { 1 });
        Array.Clear(transformed, 0, transformed.Length);

        if (!CryptoUtil.FixedTimeEquals(headerHmac, CryptoUtil.HmacSha256(BlockHmacKey(ulong.MaxValue, hmacKey), header)))
            throw new KdbxInvalidKeyException();

        var cipherText = ReadHmacBlocks(r, hmacKey);
        var plain = Decrypt(cipherId, cipherKey, iv, cipherText);
        if (compression == 1)
            plain = Gunzip(plain);

        // Inner header.
        var ir = new ByteReader(plain);
        uint streamId = 0;
        byte[]? streamKey = null;
        var binaries = new List<Binary>();
        while (true)
        {
            var id = ir.ReadByte();
            var data = ir.ReadBytes(ir.ReadInt32());
            if (id == 0) break;
            switch (id)
            {
                case 1: streamId = CryptoUtil.ReadUInt32(data, 0); break;
                case 2: streamKey = data; break;
                case 3:
                    if (data.Length < 1) throw new KdbxFormatException("Invalid attachment in the inner header.");
                    var content = new byte[data.Length - 1];
                    Buffer.BlockCopy(data, 1, content, 0, content.Length);
                    binaries.Add(new Binary((data[0] & 1) != 0, content));
                    break;
            }
        }
        if (streamKey == null)
            throw new KdbxFormatException("The inner header has no stream key.");

        var doc = ParseXml(plain, ir.Position);
        var db = new KdbxDatabase(doc, version)
        {
            cipherId = cipherId,
            compressed = compression == 1,
            kdfParameters = kdf,
            publicCustomData = publicCustomData,
        };
        db.binaries.AddRange(binaries);
        Unprotect(doc, CreateInnerStream(streamId, streamKey));
        return db;
    }

    static KdbxDatabase Load3(byte[] file, ByteReader r, uint version, KdbxKey key)
    {
        byte[]? cipherId = null, masterSeed = null, transformSeed = null, iv = null, streamKey = null, startBytes = null;
        ulong rounds = 0;
        uint compression = 0, streamId = 0;

        while (true)
        {
            var id = r.ReadByte();
            var data = r.ReadBytes(r.ReadUInt16());
            if (id == 0) break;
            switch (id)
            {
                case 2: cipherId = data; break;
                case 3: compression = CryptoUtil.ReadUInt32(data, 0); break;
                case 4: masterSeed = data; break;
                case 5: transformSeed = data; break;
                case 6: rounds = CryptoUtil.ReadUInt64(data, 0); break;
                case 7: iv = data; break;
                case 8: streamKey = data; break;
                case 9: startBytes = data; break;
                case 10: streamId = CryptoUtil.ReadUInt32(data, 0); break;
            }
        }
        int headerLength = r.Position;
        if (cipherId == null || masterSeed == null || transformSeed == null || iv == null || streamKey == null || startBytes == null)
            throw new KdbxFormatException("The database header is incomplete.");

        var kdf = new VariantDictionary();
        kdf.SetBytes("$UUID", KdbxUuids.KdfAes);
        kdf.SetUInt64("R", rounds);
        kdf.SetBytes("S", transformSeed);

        var transformed = KdbxKdf.Transform(kdf, key.GetCompositeHash());
        var cipherKey = CryptoUtil.Sha256(masterSeed, transformed);
        Array.Clear(transformed, 0, transformed.Length);

        byte[] plain;
        try
        {
            plain = Decrypt(cipherId, cipherKey, iv, r.ReadBytes(r.Remaining));
        }
        catch (CryptographicException)
        {
            throw new KdbxInvalidKeyException();
        }
        if (!CryptoUtil.StartsWith(plain, 0, startBytes))
            throw new KdbxInvalidKeyException();

        var payload = ReadHashedBlocks(plain, startBytes.Length);
        if (compression == 1)
            payload = Gunzip(payload);

        var doc = ParseXml(payload, 0);
        var db = new KdbxDatabase(doc, version)
        {
            cipherId = cipherId,
            compressed = compression == 1,
            kdfParameters = kdf,
        };

        var header = new byte[headerLength];
        Buffer.BlockCopy(file, 0, header, 0, headerLength);
        var storedHash = db.Meta.Element("HeaderHash")?.Value;
        if (!string.IsNullOrEmpty(storedHash) &&
            !CryptoUtil.FixedTimeEquals(Convert.FromBase64String(storedHash), CryptoUtil.Sha256(header)))
            throw new KdbxFormatException("The database header has been modified or is corrupt (HeaderHash mismatch).");

        Unprotect(doc, CreateInnerStream(streamId, streamKey));
        return db;
    }

    static XDocument ParseXml(byte[] data, int offset)
    {
        using var ms = new MemoryStream(data, offset, data.Length - offset);
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using var reader = XmlReader.Create(ms, settings);
        var doc = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        if (doc.Root?.Name.LocalName != "KeePassFile")
            throw new KdbxFormatException("The decrypted content is not a KeePass XML document.");
        return doc;
    }

    // ---------------------------------------------------------------- saving

    /// <summary>
    /// Saves to <paramref name="path"/> safely: writes a temporary file, checks it opens with
    /// <paramref name="key"/>, then replaces the original (keeping <c>path.bak</c> if <paramref name="keepBackup"/>).
    /// </summary>
    public void Save(string path, KdbxKey key, bool keepBackup = true)
    {
        var full = Path.GetFullPath(path);
        var temp = full + ".tmp";
        try
        {
            File.WriteAllBytes(temp, Save(key));
            Load(temp, key); // throws if anything went wrong
            if (File.Exists(full))
                File.Replace(temp, full, keepBackup ? full + ".bak" : null);
            else
                File.Move(temp, full);
        }
        finally
        {
            if (File.Exists(temp))
                File.Delete(temp);
        }
    }

    public byte[] Save(KdbxKey key) => IsKdbx4 ? Save4(key) : Save3(key);

    byte[] Save4(KdbxKey key)
    {
        var masterSeed = CryptoUtil.RandomBytes(32);
        var iv = CryptoUtil.RandomBytes(KdbxUuids.Equal(cipherId, KdbxUuids.CipherChaCha20) ? 12 : 16);
        KdbxKdf.Reseed(kdfParameters);
        var innerKey = CryptoUtil.RandomBytes(64);

        byte[] header;
        using (var h = new MemoryStream())
        {
            WriteUInt32(h, Signature1);
            WriteUInt32(h, Signature2);
            WriteUInt32(h, FileVersion);
            WriteField4(h, 2, cipherId);
            WriteField4(h, 3, CryptoUtil.UInt32Bytes(compressed ? 1u : 0u));
            WriteField4(h, 4, masterSeed);
            WriteField4(h, 7, iv);
            WriteField4(h, 11, kdfParameters.Serialize());
            if (publicCustomData != null)
                WriteField4(h, 12, publicCustomData);
            WriteField4(h, 0, EndOfHeader);
            header = h.ToArray();
        }

        var transformed = KdbxKdf.Transform(kdfParameters, key.GetCompositeHash());
        var cipherKey = CryptoUtil.Sha256(masterSeed, transformed);
        var hmacKey = CryptoUtil.Sha512(masterSeed, transformed, new byte[] { 1 });
        Array.Clear(transformed, 0, transformed.Length);

        byte[] plain;
        using (var body = new MemoryStream())
        {
            WriteField4(body, 1, CryptoUtil.UInt32Bytes(InnerStreamChaCha20));
            WriteField4(body, 2, innerKey);
            foreach (var bin in binaries)
            {
                var data = new byte[bin.Data.Length + 1];
                data[0] = (byte)(bin.Protected ? 1 : 0);
                Buffer.BlockCopy(bin.Data, 0, data, 1, bin.Data.Length);
                WriteField4(body, 3, data);
            }
            WriteField4(body, 0, Array.Empty<byte>());
            WriteXml(body, CreateInnerStream(InnerStreamChaCha20, innerKey), null);
            plain = body.ToArray();
        }
        if (compressed)
            plain = Gzip(plain);

        var cipherText = Encrypt(cipherId, cipherKey, iv, plain);

        using var output = new MemoryStream();
        output.Write(header, 0, header.Length);
        output.Write(CryptoUtil.Sha256(header), 0, 32);
        output.Write(CryptoUtil.HmacSha256(BlockHmacKey(ulong.MaxValue, hmacKey), header), 0, 32);
        WriteHmacBlocks(output, cipherText, hmacKey);
        return output.ToArray();
    }

    byte[] Save3(KdbxKey key)
    {
        if (!KdbxUuids.Equal(kdfParameters.GetBytes("$UUID"), KdbxUuids.KdfAes))
            throw new InvalidOperationException("KDBX 3.1 databases must use AES-KDF.");

        var masterSeed = CryptoUtil.RandomBytes(32);
        var iv = CryptoUtil.RandomBytes(KdbxUuids.Equal(cipherId, KdbxUuids.CipherChaCha20) ? 12 : 16);
        KdbxKdf.Reseed(kdfParameters);
        var streamKey = CryptoUtil.RandomBytes(32);
        var startBytes = CryptoUtil.RandomBytes(32);

        byte[] header;
        using (var h = new MemoryStream())
        {
            WriteUInt32(h, Signature1);
            WriteUInt32(h, Signature2);
            WriteUInt32(h, FileVersion);
            WriteField3(h, 2, cipherId);
            WriteField3(h, 3, CryptoUtil.UInt32Bytes(compressed ? 1u : 0u));
            WriteField3(h, 4, masterSeed);
            WriteField3(h, 5, kdfParameters.GetBytes("S")!);
            WriteField3(h, 6, CryptoUtil.UInt64Bytes(kdfParameters.GetUInt64("R") ?? 60000));
            WriteField3(h, 7, iv);
            WriteField3(h, 8, streamKey);
            WriteField3(h, 9, startBytes);
            WriteField3(h, 10, CryptoUtil.UInt32Bytes(InnerStreamSalsa20));
            WriteField3(h, 0, EndOfHeader);
            header = h.ToArray();
        }

        var transformed = KdbxKdf.Transform(kdfParameters, key.GetCompositeHash());
        var cipherKey = CryptoUtil.Sha256(masterSeed, transformed);
        Array.Clear(transformed, 0, transformed.Length);

        byte[] xml;
        using (var ms = new MemoryStream())
        {
            WriteXml(ms, CreateInnerStream(InnerStreamSalsa20, streamKey), Convert.ToBase64String(CryptoUtil.Sha256(header)));
            xml = ms.ToArray();
        }
        if (compressed)
            xml = Gzip(xml);

        byte[] plain;
        using (var ms = new MemoryStream())
        {
            ms.Write(startBytes, 0, startBytes.Length);
            WriteHashedBlocks(ms, xml);
            plain = ms.ToArray();
        }

        var cipherText = Encrypt(cipherId, cipherKey, iv, plain);
        var output = new byte[header.Length + cipherText.Length];
        Buffer.BlockCopy(header, 0, output, 0, header.Length);
        Buffer.BlockCopy(cipherText, 0, output, header.Length, cipherText.Length);
        return output;
    }

    /// <summary>Serialises a protected copy of the document. KDBX 3 also gets the header hash.</summary>
    void WriteXml(Stream output, StreamCipher innerStream, string? headerHash)
    {
        var copy = new XDocument(Document);
        var meta = copy.Root!.Element("Meta")!;
        meta.Element("HeaderHash")?.Remove();
        if (headerHash != null)
        {
            var generator = meta.Element("Generator");
            var element = new XElement("HeaderHash", headerHash);
            if (generator != null) generator.AddAfterSelf(element);
            else meta.AddFirst(element);
        }

        Protect(copy, innerStream);

        var settings = new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(false),
            Indent = true,
            IndentChars = "\t",
            NewLineChars = "\n",
            NewLineHandling = NewLineHandling.Entitize, // keep \r in notes intact
            CloseOutput = false,
        };
        using var writer = XmlWriter.Create(output, settings);
        copy.Save(writer);
    }

    // ---------------------------------------------------------------- protected values

    static bool IsProtected(XElement e) =>
        string.Equals((string?)e.Attribute("Protected"), "True", StringComparison.OrdinalIgnoreCase);

    static bool IsStringValue(XElement e) => e.Name.LocalName == "Value" && e.Parent?.Name.LocalName == "String";

    /// <summary>Decrypts every Protected="True" value in document order (the order the inner stream was applied).</summary>
    static void Unprotect(XDocument doc, StreamCipher stream)
    {
        foreach (var e in doc.Descendants().Where(IsProtected).ToList())
        {
            var data = Convert.FromBase64String(e.Value.Trim());
            stream.Transform(data);
            e.Value = IsStringValue(e) ? Encoding.UTF8.GetString(data) : Convert.ToBase64String(data);
            Array.Clear(data, 0, data.Length);
        }
    }

    static void Protect(XDocument doc, StreamCipher stream)
    {
        foreach (var e in doc.Descendants().Where(IsProtected).ToList())
        {
            var data = IsStringValue(e) ? Encoding.UTF8.GetBytes(e.Value) : Convert.FromBase64String(e.Value.Trim());
            stream.Transform(data);
            e.Value = Convert.ToBase64String(data);
        }
    }

    static StreamCipher CreateInnerStream(uint id, byte[] key)
    {
        switch (id)
        {
            case InnerStreamSalsa20:
                return new Salsa20(CryptoUtil.Sha256(key), Salsa20Nonce);
            case InnerStreamChaCha20:
                var h = CryptoUtil.Sha512(key);
                var k = new byte[32];
                var n = new byte[12];
                Buffer.BlockCopy(h, 0, k, 0, 32);
                Buffer.BlockCopy(h, 32, n, 0, 12);
                return new ChaCha20(k, n);
            default:
                throw new KdbxFormatException($"Unsupported inner random stream ({id}).");
        }
    }

    // ---------------------------------------------------------------- times


    /// <summary>KDBX 4 stores times as base64 seconds since 0001-01-01; KDBX 3 as ISO 8601.</summary>
    internal string FormatTime(DateTime time)
    {
        var utc = time.Kind == DateTimeKind.Local ? time.ToUniversalTime() : DateTime.SpecifyKind(time, DateTimeKind.Utc);
        if (IsKdbx4)
            return Convert.ToBase64String(CryptoUtil.UInt64Bytes((ulong)(utc.Ticks / TimeSpan.TicksPerSecond)));
        return utc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
    }

    internal static DateTime? ParseTime(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        text = text!.Trim();
        try
        {
            if (text.IndexOf(':') < 0)
            {
                var bytes = Convert.FromBase64String(text);
                if (bytes.Length == 8)
                {
                    var seconds = (long)CryptoUtil.ReadUInt64(bytes, 0);
                    if (seconds >= 0 && seconds <= DateTime.MaxValue.Ticks / TimeSpan.TicksPerSecond)
                        return new DateTime(seconds * TimeSpan.TicksPerSecond, DateTimeKind.Utc);
                }
                return null;
            }
            return DateTime.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    // ---------------------------------------------------------------- block streams & ciphers

    static byte[] BlockHmacKey(ulong index, byte[] hmacKey) => CryptoUtil.Sha512(CryptoUtil.UInt64Bytes(index), hmacKey);

    static byte[] ReadHmacBlocks(ByteReader r, byte[] hmacKey)
    {
        using var ms = new MemoryStream();
        for (ulong index = 0; ; index++)
        {
            var mac = r.ReadBytes(32);
            var size = r.ReadInt32();
            var data = r.ReadBytes(size);
            var expected = CryptoUtil.HmacSha256(BlockHmacKey(index, hmacKey),
                CryptoUtil.UInt64Bytes(index), CryptoUtil.UInt32Bytes((uint)size), data);
            if (!CryptoUtil.FixedTimeEquals(mac, expected))
                throw new KdbxFormatException("The database is corrupt (block authentication failed).");
            if (size == 0)
                return ms.ToArray();
            ms.Write(data, 0, size);
        }
    }

    static void WriteHmacBlocks(Stream output, byte[] data, byte[] hmacKey)
    {
        ulong index = 0;
        int offset = 0;
        while (true)
        {
            int size = Math.Min(BlockSize, data.Length - offset);
            var block = new byte[size];
            Buffer.BlockCopy(data, offset, block, 0, size);
            var mac = CryptoUtil.HmacSha256(BlockHmacKey(index, hmacKey),
                CryptoUtil.UInt64Bytes(index), CryptoUtil.UInt32Bytes((uint)size), block);
            output.Write(mac, 0, 32);
            output.Write(CryptoUtil.UInt32Bytes((uint)size), 0, 4);
            output.Write(block, 0, size);
            if (size == 0)
                return;
            offset += size;
            index++;
        }
    }

    static byte[] ReadHashedBlocks(byte[] data, int offset)
    {
        var r = new ByteReader(data, offset);
        using var ms = new MemoryStream();
        for (uint expectedIndex = 0; ; expectedIndex++)
        {
            if (r.ReadUInt32() != expectedIndex)
                throw new KdbxFormatException("The database is corrupt (block index mismatch).");
            var hash = r.ReadBytes(32);
            var size = r.ReadInt32();
            if (size == 0)
            {
                if (hash.Any(b => b != 0))
                    throw new KdbxFormatException("The database is corrupt (final block hash).");
                return ms.ToArray();
            }
            var block = r.ReadBytes(size);
            if (!CryptoUtil.FixedTimeEquals(hash, CryptoUtil.Sha256(block)))
                throw new KdbxFormatException("The database is corrupt (block hash mismatch).");
            ms.Write(block, 0, size);
        }
    }

    static void WriteHashedBlocks(Stream output, byte[] data)
    {
        uint index = 0;
        int offset = 0;
        while (true)
        {
            int size = Math.Min(BlockSize, data.Length - offset);
            var block = new byte[size];
            Buffer.BlockCopy(data, offset, block, 0, size);
            output.Write(CryptoUtil.UInt32Bytes(index), 0, 4);
            output.Write(size == 0 ? new byte[32] : CryptoUtil.Sha256(block), 0, 32);
            output.Write(CryptoUtil.UInt32Bytes((uint)size), 0, 4);
            output.Write(block, 0, size);
            if (size == 0)
                return;
            offset += size;
            index++;
        }
    }

    static byte[] Decrypt(byte[] cipherId, byte[] key, byte[] iv, byte[] data)
    {
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherAes256))
        {
            using var aes = CreateAes(key, iv);
            using var d = aes.CreateDecryptor();
            return d.TransformFinalBlock(data, 0, data.Length);
        }
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherChaCha20))
        {
            var copy = (byte[])data.Clone();
            new ChaCha20(key, iv).Transform(copy);
            return copy;
        }
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherTwofish))
            throw new KdbxFormatException("Databases encrypted with Twofish are not supported. Switch the cipher to AES or ChaCha20 in KeePass.");
        throw new KdbxFormatException("Unknown database cipher.");
    }

    static byte[] Encrypt(byte[] cipherId, byte[] key, byte[] iv, byte[] data)
    {
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherAes256))
        {
            using var aes = CreateAes(key, iv);
            using var e = aes.CreateEncryptor();
            return e.TransformFinalBlock(data, 0, data.Length);
        }
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherChaCha20))
        {
            var copy = (byte[])data.Clone();
            new ChaCha20(key, iv).Transform(copy);
            return copy;
        }
        throw new KdbxFormatException("Saving with this database's cipher is not supported.");
    }

    static Aes CreateAes(byte[] key, byte[] iv)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
        return aes;
    }

    static byte[] Gzip(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
            gz.Write(data, 0, data.Length);
        return ms.ToArray();
    }

    static byte[] Gunzip(byte[] data)
    {
        try
        {
            using var input = new MemoryStream(data);
            using var gz = new GZipStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            gz.CopyTo(output);
            return output.ToArray();
        }
        catch (InvalidDataException)
        {
            throw new KdbxFormatException("The database is corrupt (decompression failed).");
        }
    }

    static void WriteUInt32(Stream s, uint v) => s.Write(CryptoUtil.UInt32Bytes(v), 0, 4);

    static void WriteField4(Stream s, byte id, byte[] data)
    {
        s.WriteByte(id);
        WriteUInt32(s, (uint)data.Length);
        s.Write(data, 0, data.Length);
    }

    static void WriteField3(Stream s, byte id, byte[] data)
    {
        s.WriteByte(id);
        s.WriteByte((byte)data.Length);
        s.WriteByte((byte)(data.Length >> 8));
        s.Write(data, 0, data.Length);
    }

    sealed class Binary
    {
        public Binary(bool isProtected, byte[] data)
        {
            Protected = isProtected;
            Data = data;
        }

        public bool Protected { get; }
        public byte[] Data { get; }
    }
}
