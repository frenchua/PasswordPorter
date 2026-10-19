using System.IO;
using System.Linq;
using PasswordPorter.KeePass.Kdbx;
using Xunit;

namespace PasswordPorter.Tests;

public class KdbxTests
{
    // Small KDF settings so the tests stay fast.
    internal static KdbxKdfSettings FastKdf(KdbxKdfAlgorithm algorithm = KdbxKdfAlgorithm.Argon2id) => new KdbxKdfSettings
    {
        Algorithm = algorithm,
        MemoryBytes = 1024 * 1024,
        Iterations = algorithm == KdbxKdfAlgorithm.AesKdf ? 1000UL : 2UL,
        Parallelism = 2,
    };

    [Theory]
    [InlineData(KdbxKdfAlgorithm.Argon2id)]
    [InlineData(KdbxKdfAlgorithm.Argon2d)]
    [InlineData(KdbxKdfAlgorithm.AesKdf)]
    public void RoundTrip_PreservesEntries(KdbxKdfAlgorithm kdf)
    {
        var db = KdbxDatabase.Create("Test", FastKdf(kdf));
        var entry = db.RootGroup.GetOrAddGroup("Web").AddEntry();
        entry.SetString("Title", "Example");
        entry.SetString("UserName", "alice");
        entry.SetString("Password", "p@ss wörd ☃ \r\n", protect: true);
        entry.SetString("Notes", "line1\r\nline2\n");
        entry.SetString("TOTP Secret", "JBSWY3DP", protect: true);

        var key = new KdbxKey("master");
        var loaded = KdbxDatabase.Load(db.Save(key), key);

        Assert.Equal(0x00040000u, loaded.FileVersion);
        var e = loaded.RootGroup.Groups.Single(g => g.Name == "Web").Entries.Single();
        Assert.Equal("Example", e.GetString("Title"));
        Assert.Equal("alice", e.GetString("UserName"));
        Assert.Equal("p@ss wörd ☃ \r\n", e.GetString("Password"));
        Assert.Equal("line1\r\nline2\n", e.GetString("Notes"));
        Assert.Equal("JBSWY3DP", e.GetString("TOTP Secret"));
    }

    [Fact]
    public void ProtectedValues_AreNotStoredInClearText()
    {
        var db = KdbxDatabase.Create("Test", FastKdf());
        db.RootGroup.AddEntry().SetString("Password", "hunter2-very-unique", protect: true);
        var bytes = db.Save(new KdbxKey("k"));
        Assert.DoesNotContain("hunter2", System.Text.Encoding.UTF8.GetString(bytes));
        // The in-memory document still holds the plain value after saving.
        Assert.Equal("hunter2-very-unique", db.RootGroup.Entries.Single().GetString("Password"));
    }

    [Fact]
    public void WrongPassword_Throws()
    {
        var db = KdbxDatabase.Create("Test", FastKdf());
        var bytes = db.Save(new KdbxKey("right"));
        Assert.Throws<KdbxInvalidKeyException>(() => KdbxDatabase.Load(bytes, new KdbxKey("wrong")));
    }

    [Fact]
    public void KeyFile_AloneAndCombined()
    {
        using var dir = new TempDir();
        var keyFile = dir.File("db.keyx");
        KdbxKey.CreateKeyFile(keyFile);

        var db = KdbxDatabase.Create("Test", FastKdf());
        var both = new KdbxKey("pw", keyFile);
        KdbxDatabase.Load(db.Save(both), both);
        Assert.Throws<KdbxInvalidKeyException>(() => KdbxDatabase.Load(db.Save(both), new KdbxKey("pw")));

        var fileOnly = new KdbxKey(null, keyFile);
        KdbxDatabase.Load(db.Save(fileOnly), fileOnly);
    }

    [Fact]
    public void SaveToPath_KeepsBackupOfPreviousVersion()
    {
        using var dir = new TempDir();
        var path = dir.File("db.kdbx");
        var key = new KdbxKey("pw");
        var db = KdbxDatabase.Create("Test", FastKdf());
        db.Save(path, key);
        db.RootGroup.AddEntry().SetString("Title", "second");
        db.Save(path, key);

        Assert.True(File.Exists(path + ".bak"));
        Assert.False(File.Exists(path + ".tmp"));
        Assert.Empty(KdbxDatabase.Load(path + ".bak", key).RootGroup.Entries);
        Assert.Single(KdbxDatabase.Load(path, key).RootGroup.Entries);
    }

    [Fact]
    public void Times_RoundTripInKdbx4Format()
    {
        var t = new System.DateTime(2024, 5, 6, 7, 8, 9, System.DateTimeKind.Utc);
        var db = KdbxDatabase.Create("Test", FastKdf());
        var e = db.RootGroup.AddEntry();
        e.SetTimes(t, t, t);
        Assert.Equal(t, KdbxDatabase.ParseTime(db.FormatTime(t)));
        Assert.Equal(t, e.CreationTime);
        Assert.Equal(t, KdbxDatabase.ParseTime("2024-05-06T07:08:09Z"));
    }

    [Fact]
    public void NotAKeePassFile_IsRejected()
    {
        Assert.Throws<KdbxFormatException>(() => KdbxDatabase.Load(new byte[64], new KdbxKey("x")));
    }
}
