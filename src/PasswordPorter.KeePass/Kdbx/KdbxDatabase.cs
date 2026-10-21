using System.Globalization;
using System.IO.Compression;
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

    static readonly byte[] EndOfHeader = [0x0D, 0x0A, 0x0D, 0x0A];
    static readonly byte[] Salsa20Nonce = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
    const uint InnerStreamSalsa20 = 2;
    const uint InnerStreamChaCha20 = 3;

    /// <summary>An attachment from the KDBX 4 inner header.</summary>
    sealed record Binary(bool Protected, byte[] Data);

    byte[] cipherId = KdbxUuids.CipherAes256;
    bool compressed = true;
    VariantDictionary kdfParameters = new KdbxKdfSettings().ToParameters();
    byte[]? publicCustomData;
    readonly List<Binary> binaries = [];

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
        new(this, Document.Root?.Element("Root")?.Element("Group") ?? throw new KdbxFormatException("The database has no root group."));

    public string? RecycleBinUuid =>
        Meta.Element("RecycleBinEnabled")?.Value is { } enabled && enabled.Equals("False", StringComparison.OrdinalIgnoreCase)
            ? null
            : Meta.Element("RecycleBinUUID")?.Value is { Length: > 0 } uuid && uuid != KdbxGroup.ZeroUuid ? uuid : null;

    // ---------------------------------------------------------------- creation

    public static KdbxDatabase Create(string name, KdbxKdfSettings? kdf = null) => Create(name, kdf, FileVersion40);

    /// <summary>Creates a database in a specific format version (KDBX 3.1 requires AES-KDF). Used by tests.</summary>
    internal static KdbxDatabase Create(string name, KdbxKdfSettings? kdf, uint fileVersion)
    {
        var db = new KdbxDatabase(new XDocument(new XDeclaration("1.0", "utf-8", "yes")), fileVersion)
        {
            kdfParameters = (kdf ?? new KdbxKdfSettings()).ToParameters(),
        };

        var now = db.FormatTime(DateTime.UtcNow);
        var zero = KdbxGroup.ZeroUuid;
        db.Document.Add(new XElement("KeePassFile",
            new XElement("Meta",
                new XElement("Generator", "PasswordPorter"),
                new XElement("DatabaseName", name),
                new XElement("DatabaseNameChanged", now),
                new XElement("DatabaseDescription"),
                new XElement("DatabaseDescriptionChanged", now),
                new XElement("DefaultUserName"),
                new XElement("DefaultUserNameChanged", now),
                new XElement("MaintenanceHistoryDays", 365),
                new XElement("Color"),
                new XElement("MasterKeyChanged", now),
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
                new XElement("RecycleBinChanged", now),
                new XElement("EntryTemplatesGroup", zero),
                new XElement("EntryTemplatesGroupChanged", now),
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
        switch ((r.ReadUInt32(), r.ReadUInt32()))
        {
            case (Signature1, Signature2):
                break;
            case (Signature1, Signature2Kdb):
                throw new KdbxFormatException("This is a KeePass 1.x (.kdb) database, which is not supported. Open it in KeePass 2 and save it as .kdbx.");
            default:
                throw new KdbxFormatException("Not a KeePass database.");
        }

        var version = r.ReadUInt32();
        return (version >> 16) switch
        {
            3 => Load3(file, r, version, key),
            4 => Load4(file, r, version, key),
            _ => throw new KdbxFormatException($"Unsupported KDBX version {version >> 16}.{version & 0xFFFF}."),
        };
    }

    static KdbxDatabase Load4(byte[] file, ByteReader r, uint version, KdbxKey key)
    {
        byte[]? cipherId = null, masterSeed = null, iv = null, publicCustomData = null;
        uint compression = 0;
        VariantDictionary? kdf = null;

        for (var (id, data) = ReadField4(r); id != 0; (id, data) = ReadField4(r))
        {
            switch (id)
            {
                case 2: cipherId = data; break;
                case 3: compression = BinaryPrimitives.ReadUInt32LittleEndian(data); break;
                case 4: masterSeed = data; break;
                case 7: iv = data; break;
                case 11: kdf = VariantDictionary.Deserialize(data); break;
                case 12: publicCustomData = data; break;
            }
        }
        if (cipherId is null || masterSeed is null || iv is null || kdf is null)
            throw new KdbxFormatException("The database header is incomplete.");

        var header = file[..r.Position];
        if (!CryptographicOperations.FixedTimeEquals(r.ReadBytes(32), CryptoUtil.Sha256(header)))
            throw new KdbxFormatException("The database header is corrupt (checksum mismatch).");
        var headerHmac = r.ReadBytes(32);

        var (cipherKey, hmacKey) = DeriveKeys4(kdf, key, masterSeed);
        if (!CryptographicOperations.FixedTimeEquals(headerHmac, CryptoUtil.HmacSha256(BlockHmacKey(ulong.MaxValue, hmacKey), header)))
            throw new KdbxInvalidKeyException();

        var plain = Decrypt(cipherId, cipherKey, iv, ReadHmacBlocks(r, hmacKey));
        if (compression == 1)
            plain = Gunzip(plain);

        // Inner header.
        var ir = new ByteReader(plain);
        uint streamId = 0;
        byte[]? streamKey = null;
        List<Binary> binaries = [];
        for (var (id, data) = ReadField4(ir); id != 0; (id, data) = ReadField4(ir))
        {
            switch (id, data)
            {
                case (1, _): streamId = BinaryPrimitives.ReadUInt32LittleEndian(data); break;
                case (2, _): streamKey = data; break;
                case (3, [var flags, .. var content]): binaries.Add(new((flags & 1) != 0, content)); break;
                case (3, _): throw new KdbxFormatException("Invalid attachment in the inner header.");
            }
        }
        if (streamKey is null)
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

        for (var (id, data) = ReadField3(r); id != 0; (id, data) = ReadField3(r))
        {
            switch (id)
            {
                case 2: cipherId = data; break;
                case 3: compression = BinaryPrimitives.ReadUInt32LittleEndian(data); break;
                case 4: masterSeed = data; break;
                case 5: transformSeed = data; break;
                case 6: rounds = BinaryPrimitives.ReadUInt64LittleEndian(data); break;
                case 7: iv = data; break;
                case 8: streamKey = data; break;
                case 9: startBytes = data; break;
                case 10: streamId = BinaryPrimitives.ReadUInt32LittleEndian(data); break;
            }
        }
        if (cipherId is null || masterSeed is null || transformSeed is null || iv is null || streamKey is null || startBytes is null)
            throw new KdbxFormatException("The database header is incomplete.");
        var header = file[..r.Position];

        var kdf = new VariantDictionary();
        kdf.SetBytes("$UUID", KdbxUuids.KdfAes);
        kdf.SetUInt64("R", rounds);
        kdf.SetBytes("S", transformSeed);
        var cipherKey = DeriveCipherKey3(kdf, key, masterSeed);

        byte[] plain;
        try
        {
            plain = Decrypt(cipherId, cipherKey, iv, r.ReadBytes(r.Remaining));
        }
        catch (CryptographicException)
        {
            throw new KdbxInvalidKeyException();
        }
        if (!plain.AsSpan().StartsWith(startBytes))
            throw new KdbxInvalidKeyException();

        var payload = ReadHashedBlocks(plain, startBytes.Length);
        if (compression == 1)
            payload = Gunzip(payload);

        var doc = ParseXml(payload);
        var db = new KdbxDatabase(doc, version)
        {
            cipherId = cipherId,
            compressed = compression == 1,
            kdfParameters = kdf,
        };

        if (db.Meta.Element("HeaderHash")?.Value is { Length: > 0 } storedHash
            && !CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(storedHash), CryptoUtil.Sha256(header)))
            throw new KdbxFormatException("The database header has been modified or is corrupt (HeaderHash mismatch).");

        Unprotect(doc, CreateInnerStream(streamId, streamKey));
        return db;
    }

    static (byte id, byte[] data) ReadField4(ByteReader r) => (r.ReadByte(), r.ReadBytes(r.ReadInt32()));

    static (byte id, byte[] data) ReadField3(ByteReader r) => (r.ReadByte(), r.ReadBytes(r.ReadUInt16()));

    static XDocument ParseXml(byte[] data, int offset = 0)
    {
        using var stream = new MemoryStream(data, offset, data.Length - offset, writable: false);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        var doc = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        return doc.Root?.Name.LocalName == "KeePassFile"
            ? doc
            : throw new KdbxFormatException("The decrypted content is not a KeePass XML document.");
    }

    /// <summary>KDBX 4: the payload cipher key and the HMAC base key.</summary>
    static (byte[] cipherKey, byte[] hmacKey) DeriveKeys4(VariantDictionary kdf, KdbxKey key, byte[] masterSeed)
    {
        var transformed = KdbxKdf.Transform(kdf, key.GetCompositeHash());
        try
        {
            return (CryptoUtil.Sha256(masterSeed, transformed), CryptoUtil.Sha512(masterSeed, transformed, [1]));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transformed);
        }
    }

    static byte[] DeriveCipherKey3(VariantDictionary kdf, KdbxKey key, byte[] masterSeed)
    {
        var transformed = KdbxKdf.Transform(kdf, key.GetCompositeHash());
        try
        {
            return CryptoUtil.Sha256(masterSeed, transformed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transformed);
        }
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
            File.Delete(temp);
        }
    }

    public byte[] Save(KdbxKey key) => IsKdbx4 ? Save4(key) : Save3(key);

    int IvLength => KdbxUuids.Equal(cipherId, KdbxUuids.CipherChaCha20) ? 12 : 16;

    byte[] Save4(KdbxKey key)
    {
        var masterSeed = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(IvLength);
        KdbxKdf.Reseed(kdfParameters);
        var innerKey = RandomNumberGenerator.GetBytes(64);

        byte[] header;
        using (var h = new MemoryStream())
        {
            WriteHeaderStart(h);
            WriteField4(h, 2, cipherId);
            WriteField4(h, 3, CryptoUtil.UInt32Bytes(compressed ? 1u : 0u));
            WriteField4(h, 4, masterSeed);
            WriteField4(h, 7, iv);
            WriteField4(h, 11, kdfParameters.Serialize());
            if (publicCustomData is not null)
                WriteField4(h, 12, publicCustomData);
            WriteField4(h, 0, EndOfHeader);
            header = h.ToArray();
        }

        var (cipherKey, hmacKey) = DeriveKeys4(kdfParameters, key, masterSeed);

        byte[] plain;
        using (var body = new MemoryStream())
        {
            WriteField4(body, 1, CryptoUtil.UInt32Bytes(InnerStreamChaCha20));
            WriteField4(body, 2, innerKey);
            foreach (var bin in binaries)
                WriteField4(body, 3, [(byte)(bin.Protected ? 1 : 0), .. bin.Data]);
            WriteField4(body, 0, []);
            WriteXml(body, CreateInnerStream(InnerStreamChaCha20, innerKey), headerHash: null);
            plain = body.ToArray();
        }
        if (compressed)
            plain = Gzip(plain);

        using var output = new MemoryStream();
        output.Write(header);
        output.Write(CryptoUtil.Sha256(header));
        output.Write(CryptoUtil.HmacSha256(BlockHmacKey(ulong.MaxValue, hmacKey), header));
        WriteHmacBlocks(output, Encrypt(cipherId, cipherKey, iv, plain), hmacKey);
        return output.ToArray();
    }

    byte[] Save3(KdbxKey key)
    {
        if (!KdbxUuids.Equal(kdfParameters.GetBytes("$UUID"), KdbxUuids.KdfAes))
            throw new InvalidOperationException("KDBX 3.1 databases must use AES-KDF.");

        var masterSeed = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(IvLength);
        KdbxKdf.Reseed(kdfParameters);
        var streamKey = RandomNumberGenerator.GetBytes(32);
        var startBytes = RandomNumberGenerator.GetBytes(32);

        byte[] header;
        using (var h = new MemoryStream())
        {
            WriteHeaderStart(h);
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

        var cipherKey = DeriveCipherKey3(kdfParameters, key, masterSeed);

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
            ms.Write(startBytes);
            WriteHashedBlocks(ms, xml);
            plain = ms.ToArray();
        }

        return [.. header, .. Encrypt(cipherId, cipherKey, iv, plain)];
    }

    void WriteHeaderStart(Stream s)
    {
        s.Write(CryptoUtil.UInt32Bytes(Signature1));
        s.Write(CryptoUtil.UInt32Bytes(Signature2));
        s.Write(CryptoUtil.UInt32Bytes(FileVersion));
    }

    /// <summary>Serialises a protected copy of the document. KDBX 3 also gets the header hash.</summary>
    void WriteXml(Stream output, StreamCipher innerStream, string? headerHash)
    {
        var copy = new XDocument(Document);
        var meta = copy.Root!.Element("Meta")!;
        meta.Element("HeaderHash")?.Remove();
        if (headerHash is not null)
        {
            var element = new XElement("HeaderHash", headerHash);
            if (meta.Element("Generator") is { } generator) generator.AddAfterSelf(element);
            else meta.AddFirst(element);
        }

        Protect(copy, innerStream);

        using var writer = XmlWriter.Create(output, new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(false),
            Indent = true,
            IndentChars = "\t",
            NewLineChars = "\n",
            NewLineHandling = NewLineHandling.Entitize, // keep \r in notes intact
            CloseOutput = false,
        });
        copy.Save(writer);
    }

    // ---------------------------------------------------------------- protected values

    static bool IsProtected(XElement e) =>
        string.Equals((string?)e.Attribute("Protected"), "True", StringComparison.OrdinalIgnoreCase);

    static bool IsStringValue(XElement e) => e is { Name.LocalName: "Value", Parent.Name.LocalName: "String" };

    /// <summary>Decrypts every Protected="True" value in document order (the order the inner stream was applied).</summary>
    static void Unprotect(XDocument doc, StreamCipher stream)
    {
        foreach (var e in doc.Descendants().Where(IsProtected).ToList())
        {
            var data = Convert.FromBase64String(e.Value.Trim());
            stream.Transform(data);
            e.Value = IsStringValue(e) ? Encoding.UTF8.GetString(data) : Convert.ToBase64String(data);
            CryptographicOperations.ZeroMemory(data);
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

    static StreamCipher CreateInnerStream(uint id, byte[] key) => id switch
    {
        InnerStreamSalsa20 => new Salsa20(CryptoUtil.Sha256(key), Salsa20Nonce),
        InnerStreamChaCha20 when CryptoUtil.Sha512(key) is var h => new ChaCha20(h.AsSpan(0, 32), h.AsSpan(32, 12)),
        _ => throw new KdbxFormatException($"Unsupported inner random stream ({id})."),
    };

    // ---------------------------------------------------------------- times

    /// <summary>KDBX 4 stores times as base64 seconds since 0001-01-01; KDBX 3 as ISO 8601.</summary>
    internal string FormatTime(DateTime time)
    {
        var utc = time.Kind == DateTimeKind.Local ? time.ToUniversalTime() : DateTime.SpecifyKind(time, DateTimeKind.Utc);
        return IsKdbx4
            ? Convert.ToBase64String(CryptoUtil.UInt64Bytes((ulong)(utc.Ticks / TimeSpan.TicksPerSecond)))
            : utc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
    }

    internal static DateTime? ParseTime(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        text = text.Trim();
        try
        {
            if (text.Contains(':'))
                return DateTime.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);

            return Convert.FromBase64String(text) is { Length: 8 } bytes
                   && BinaryPrimitives.ReadInt64LittleEndian(bytes) is var seconds and >= 0
                   && seconds <= DateTime.MaxValue.Ticks / TimeSpan.TicksPerSecond
                ? new DateTime(seconds * TimeSpan.TicksPerSecond, DateTimeKind.Utc)
                : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    // ---------------------------------------------------------------- block streams & ciphers

    static byte[] BlockHmacKey(ulong index, byte[] hmacKey) => CryptoUtil.Sha512(CryptoUtil.UInt64Bytes(index), hmacKey);

    static byte[] BlockHmac(ulong index, byte[] hmacKey, byte[] block) =>
        CryptoUtil.HmacSha256(BlockHmacKey(index, hmacKey), CryptoUtil.UInt64Bytes(index), CryptoUtil.UInt32Bytes((uint)block.Length), block);

    static byte[] ReadHmacBlocks(ByteReader r, byte[] hmacKey)
    {
        using var ms = new MemoryStream();
        for (ulong index = 0; ; index++)
        {
            var mac = r.ReadBytes(32);
            var block = r.ReadBytes(r.ReadInt32());
            if (!CryptographicOperations.FixedTimeEquals(mac, BlockHmac(index, hmacKey, block)))
                throw new KdbxFormatException("The database is corrupt (block authentication failed).");
            if (block is [])
                return ms.ToArray();
            ms.Write(block);
        }
    }

    static void WriteHmacBlocks(Stream output, byte[] data, byte[] hmacKey)
    {
        foreach (var (index, block) in Blocks(data))
        {
            output.Write(BlockHmac(index, hmacKey, block));
            output.Write(CryptoUtil.UInt32Bytes((uint)block.Length));
            output.Write(block);
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
                return hash.AsSpan().ContainsAnyExcept((byte)0)
                    ? throw new KdbxFormatException("The database is corrupt (final block hash).")
                    : ms.ToArray();
            }
            var block = r.ReadBytes(size);
            if (!CryptographicOperations.FixedTimeEquals(hash, CryptoUtil.Sha256(block)))
                throw new KdbxFormatException("The database is corrupt (block hash mismatch).");
            ms.Write(block);
        }
    }

    static void WriteHashedBlocks(Stream output, byte[] data)
    {
        foreach (var (index, block) in Blocks(data))
        {
            output.Write(CryptoUtil.UInt32Bytes((uint)index));
            output.Write(block is [] ? new byte[32] : CryptoUtil.Sha256(block));
            output.Write(CryptoUtil.UInt32Bytes((uint)block.Length));
            output.Write(block);
        }
    }

    /// <summary>Splits data into numbered blocks of up to <see cref="BlockSize"/>, followed by an empty terminator block.</summary>
    static IEnumerable<(ulong index, byte[] block)> Blocks(byte[] data)
    {
        ulong index = 0;
        foreach (var chunk in data.Chunk(BlockSize))
            yield return (index++, chunk);
        yield return (index, []);
    }

    static byte[] Decrypt(byte[] cipherId, byte[] key, byte[] iv, byte[] data)
    {
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherAes256))
        {
            using var aes = Aes.Create();
            aes.Key = key;
            return aes.DecryptCbc(data, iv, PaddingMode.PKCS7);
        }
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherChaCha20))
            return ChaCha20Transform(key, iv, data);
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherTwofish))
            throw new KdbxFormatException("Databases encrypted with Twofish are not supported. Switch the cipher to AES or ChaCha20 in KeePass.");
        throw new KdbxFormatException("Unknown database cipher.");
    }

    static byte[] Encrypt(byte[] cipherId, byte[] key, byte[] iv, byte[] data)
    {
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherAes256))
        {
            using var aes = Aes.Create();
            aes.Key = key;
            return aes.EncryptCbc(data, iv, PaddingMode.PKCS7);
        }
        if (KdbxUuids.Equal(cipherId, KdbxUuids.CipherChaCha20))
            return ChaCha20Transform(key, iv, data);
        throw new KdbxFormatException("Saving with this database's cipher is not supported.");
    }

    static byte[] ChaCha20Transform(byte[] key, byte[] iv, byte[] data)
    {
        var copy = (byte[])data.Clone();
        new ChaCha20(key, iv).Transform(copy);
        return copy;
    }

    static byte[] Gzip(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
            gz.Write(data);
        return ms.ToArray();
    }

    static byte[] Gunzip(byte[] data)
    {
        try
        {
            using var gz = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
            using var output = new MemoryStream();
            gz.CopyTo(output);
            return output.ToArray();
        }
        catch (InvalidDataException)
        {
            throw new KdbxFormatException("The database is corrupt (decompression failed).");
        }
    }

    static void WriteField4(Stream s, byte id, byte[] data)
    {
        s.WriteByte(id);
        s.Write(CryptoUtil.UInt32Bytes((uint)data.Length));
        s.Write(data);
    }

    static void WriteField3(Stream s, byte id, byte[] data)
    {
        s.WriteByte(id);
        s.Write(CryptoUtil.UInt32Bytes((uint)data.Length).AsSpan(0, 2));
        s.Write(data);
    }
}
