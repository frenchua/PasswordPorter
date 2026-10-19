#if HAVE_KEEPASSLIB
using System.Linq;
using System.Text;
using KeePassLib;
using KeePassLib.Cryptography.KeyDerivation;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using PasswordPorter.KeePass.Kdbx;
using Xunit;

namespace PasswordPorter.Tests;

/// <summary>
/// Checks our KDBX code against KeePassLib from the real KeePass.exe, in both directions.
/// </summary>
public class KeePassLibInteropTests
{
    static CompositeKey KeePassKey(string password, string? keyFile = null)
    {
        var k = new CompositeKey();
        k.AddUserKey(new KcpPassword(password));
        if (keyFile != null)
            k.AddUserKey(new KcpKeyFile(keyFile));
        return k;
    }

    static PwDatabase OpenWithKeePass(string path, CompositeKey key)
    {
        var db = new PwDatabase();
        db.Open(IOConnectionInfo.FromPath(path), key, new NullStatusLogger());
        return db;
    }

    [Theory]
    [InlineData(KdbxKdfAlgorithm.Argon2id)]
    [InlineData(KdbxKdfAlgorithm.Argon2d)]
    [InlineData(KdbxKdfAlgorithm.AesKdf)]
    public void KeePassOpensOurDatabase(KdbxKdfAlgorithm kdf)
    {
        using var dir = new TempDir();
        var path = dir.File("ours.kdbx");
        var keyFile = dir.File("ours.keyx");
        KdbxKey.CreateKeyFile(keyFile);

        var db = KdbxDatabase.Create("Ours", KdbxTests.FastKdf(kdf));
        var e = db.RootGroup.GetOrAddGroup("Imported").GetOrAddGroup("Sub").AddEntry();
        e.SetString("Title", "Example");
        e.SetString("UserName", "alice");
        e.SetString("Password", "p@ss wörd ☃", protect: true);
        e.SetString("URL", "https://example.com");
        e.SetString("Notes", "a\r\nb");
        e.SetString("Custom", "value");
        db.Save(path, new KdbxKey("master", keyFile));

        var kp = OpenWithKeePass(path, KeePassKey("master", keyFile));
        try
        {
            var entry = kp.RootGroup.GetEntries(true).Single();
            Assert.Equal("Example", entry.Strings.ReadSafe(PwDefs.TitleField));
            Assert.Equal("alice", entry.Strings.ReadSafe(PwDefs.UserNameField));
            Assert.Equal("p@ss wörd ☃", entry.Strings.ReadSafe(PwDefs.PasswordField));
            Assert.True(entry.Strings.Get(PwDefs.PasswordField).IsProtected);
            Assert.Equal("https://example.com", entry.Strings.ReadSafe(PwDefs.UrlField));
            Assert.Equal("a\r\nb", entry.Strings.ReadSafe(PwDefs.NotesField));
            Assert.Equal("value", entry.Strings.ReadSafe("Custom"));
            Assert.Equal("Sub", entry.ParentGroup.Name);
            Assert.Equal("Imported", entry.ParentGroup.ParentGroup.Name);
        }
        finally
        {
            kp.Close();
        }
    }

    [Fact]
    public void KeePassOpensOurKdbx31Database()
    {
        using var dir = new TempDir();
        var path = dir.File("v3.kdbx");
        var db = KdbxDatabase.Create("V3", KdbxTests.FastKdf(KdbxKdfAlgorithm.AesKdf), KdbxDatabase.FileVersion31);
        var e = db.RootGroup.AddEntry();
        e.SetString("Title", "Old format");
        e.SetString("Password", "p@ss ☃", protect: true);
        e.SetString("Notes", "two\r\nlines");
        var key = new KdbxKey("master");
        db.Save(path, key);

        var reloaded = KdbxDatabase.Load(path, key);
        Assert.Equal(KdbxDatabase.FileVersion31, reloaded.FileVersion);
        Assert.Equal("p@ss ☃", reloaded.RootGroup.Entries.Single().GetString("Password"));

        var kp = OpenWithKeePass(path, KeePassKey("master"));
        try
        {
            var entry = kp.RootGroup.GetEntries(true).Single();
            Assert.Equal("Old format", entry.Strings.ReadSafe(PwDefs.TitleField));
            Assert.Equal("p@ss ☃", entry.Strings.ReadSafe(PwDefs.PasswordField));
            Assert.Equal("two\r\nlines", entry.Strings.ReadSafe(PwDefs.NotesField));
        }
        finally
        {
            kp.Close();
        }
    }

    [Theory]
    [InlineData("aes", false)]
    [InlineData("argon2d", false)]
    [InlineData("argon2id", true)]  // KDBX 4 with ChaCha20 outer cipher
    public void WeReadAndMergeIntoKeePassDatabase(string kdf, bool chacha)
    {
        using var dir = new TempDir();
        var path = dir.File("theirs.kdbx");
        var key = KeePassKey("master");

        // KeePass creates a database with an attachment and history.
        var kp = new PwDatabase();
        kp.New(IOConnectionInfo.FromPath(path), key);
        if (kdf == "aes")
        {
            var p = new AesKdf().GetDefaultParameters();
            p.SetUInt64(AesKdf.ParamRounds, 1000);
            kp.KdfParameters = p;
        }
        else
        {
            var engine = kdf == "argon2d" ? new Argon2Kdf(Argon2Type.D) : new Argon2Kdf(Argon2Type.ID);
            var p = engine.GetDefaultParameters();
            p.SetUInt64(Argon2Kdf.ParamMemory, 1024 * 1024);
            p.SetUInt64(Argon2Kdf.ParamIterations, 2);
            kp.KdfParameters = p;
        }
        if (chacha)
            kp.DataCipherUuid = new PwUuid(PasswordPorter.KeePass.Crypto.CryptoUtil.FromHex("d6038a2b8b6f4cb5a524339a31dbb59a"));

        var entry = new PwEntry(true, true);
        entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "Theirs"));
        entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, "bob"));
        entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "old"));
        entry.Binaries.Set("note.txt", new ProtectedBinary(false, Encoding.UTF8.GetBytes("attachment body")));
        kp.RootGroup.AddEntry(entry, true);
        entry.CreateBackup(kp);
        entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "new"));
        kp.Save(new NullStatusLogger());
        kp.Close();

        // We read it...
        var ourKey = new KdbxKey("master");
        var ours = KdbxDatabase.Load(path, ourKey);
        Assert.Equal(4u, ours.FileVersion >> 16); // KeePass 2.6x writes KDBX 4 even with AES-KDF
        var e = ours.RootGroup.Entries.Single();
        Assert.Equal("Theirs", e.GetString("Title"));
        Assert.Equal("new", e.GetString("Password"));

        // ...add an entry and save in the same format...
        var added = ours.RootGroup.AddEntry();
        added.SetString("Title", "Added by us");
        added.SetString("Password", "fresh", protect: true);
        ours.Save(path, ourKey);

        // ...and KeePass still sees everything, including history and the attachment.
        kp = OpenWithKeePass(path, key);
        try
        {
            var entries = kp.RootGroup.GetEntries(true).ToList();
            Assert.Equal(2, entries.Count);
            var theirs = entries.Single(x => x.Strings.ReadSafe(PwDefs.TitleField) == "Theirs");
            Assert.Equal("new", theirs.Strings.ReadSafe(PwDefs.PasswordField));
            Assert.Equal("old", theirs.History.Single().Strings.ReadSafe(PwDefs.PasswordField));
            Assert.Equal("attachment body", Encoding.UTF8.GetString(theirs.Binaries.Get("note.txt").ReadData()));
            Assert.Equal("fresh", entries.Single(x => x.Strings.ReadSafe(PwDefs.TitleField) == "Added by us").Strings.ReadSafe(PwDefs.PasswordField));
        }
        finally
        {
            kp.Close();
        }
    }
}
#endif
