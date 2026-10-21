#if HAVE_KEEPASSCHECK
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using PasswordPorter.KeePass.Kdbx;
using Xunit;

namespace PasswordPorter.Tests;

/// <summary>
/// Checks our KDBX code against KeePassLib from the real KeePass.exe, in both directions.
/// KeePassLib only runs on .NET Framework, so it is driven through the KeePassCheck helper process.
/// </summary>
public class KeePassLibInteropTests
{
    static readonly string HelperExe = typeof(KeePassLibInteropTests).Assembly
        .GetCustomAttributes<AssemblyMetadataAttribute>().Single(a => a.Key == "KeePassCheckExe").Value!;

    static string RunHelper(params string[] args)
    {
        var start = new ProcessStartInfo(HelperExe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            UseShellExecute = false,
        };
        foreach (var a in args)
            start.ArgumentList.Add(a);

        using var process = Process.Start(start)!;
        var stderr = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"KeePassCheck {args[0]} failed ({process.ExitCode}):\n{stderr.Result}");
        return stdout;
    }

    /// <summary>KeePassLib's view of a database's entries.</summary>
    static List<JsonElement> KeePassEntries(string path, string password, string? keyFile = null)
    {
        var json = keyFile is null ? RunHelper("dump", path, password) : RunHelper("dump", path, password, keyFile);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("entries").EnumerateArray().Select(e => e.Clone()).ToList();
    }

    static string Str(JsonElement entry, string key) => entry.GetProperty("strings").GetProperty(key).GetString()!;

    static bool IsProtected(JsonElement entry, string key) =>
        entry.GetProperty("protected").EnumerateArray().Any(k => k.GetString() == key);

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

        var entry = Assert.Single(KeePassEntries(path, "master", keyFile));
        Assert.Equal("Imported/Sub", entry.GetProperty("group").GetString());
        Assert.Equal("Example", Str(entry, "Title"));
        Assert.Equal("alice", Str(entry, "UserName"));
        Assert.Equal("p@ss wörd ☃", Str(entry, "Password"));
        Assert.True(IsProtected(entry, "Password"));
        Assert.Equal("https://example.com", Str(entry, "URL"));
        Assert.Equal("a\r\nb", Str(entry, "Notes"));
        Assert.Equal("value", Str(entry, "Custom"));
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

        var entry = Assert.Single(KeePassEntries(path, "master"));
        Assert.Equal("Old format", Str(entry, "Title"));
        Assert.Equal("p@ss ☃", Str(entry, "Password"));
        Assert.Equal("two\r\nlines", Str(entry, "Notes"));
    }

    [Theory]
    [InlineData("aes", "aes")]
    [InlineData("argon2d", "aes")]
    [InlineData("argon2id", "chacha20")]
    public void WeReadAndMergeIntoKeePassDatabase(string kdf, string cipher)
    {
        using var dir = new TempDir();
        var path = dir.File("theirs.kdbx");
        RunHelper("create", path, "master", kdf, cipher);

        // We read it...
        var key = new KdbxKey("master");
        var ours = KdbxDatabase.Load(path, key);
        Assert.Equal(4u, ours.FileVersion >> 16); // KeePass 2.6x writes KDBX 4 even with AES-KDF
        var e = ours.RootGroup.Entries.Single();
        Assert.Equal("Theirs", e.GetString("Title"));
        Assert.Equal("new", e.GetString("Password"));

        // ...add an entry and save in the same format...
        var added = ours.RootGroup.AddEntry();
        added.SetString("Title", "Added by us");
        added.SetString("Password", "fresh", protect: true);
        ours.Save(path, key);

        // ...and KeePass still sees everything, including history and the attachment.
        var entries = KeePassEntries(path, "master");
        Assert.Equal(2, entries.Count);
        var theirs = entries.Single(x => Str(x, "Title") == "Theirs");
        Assert.Equal("new", Str(theirs, "Password"));
        Assert.Equal("old", theirs.GetProperty("history").EnumerateArray().Single().GetProperty("Password").GetString());
        Assert.Equal("attachment body",
            Encoding.UTF8.GetString(Convert.FromBase64String(theirs.GetProperty("binaries").GetProperty("note.txt").GetString()!)));
        Assert.Equal("fresh", Str(entries.Single(x => Str(x, "Title") == "Added by us"), "Password"));
    }
}
#endif
