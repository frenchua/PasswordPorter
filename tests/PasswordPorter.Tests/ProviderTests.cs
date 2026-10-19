using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PasswordPorter.Firefox;
using PasswordPorter.KeePass;
using PasswordPorter.KeePass.Kdbx;
using PasswordPorter.Providers;
using PasswordPorter.Providers.Csv;
using PasswordPorter.Text;
using Xunit;

namespace PasswordPorter.Tests;

public class ProviderTests
{
    static Dictionary<string, string> Opts(params string[] pairs) =>
        pairs.Select(p => p.Split(new[] { '=' }, 2)).ToDictionary(p => p[0], p => p[1]);

    static readonly string[] FastKdfOptions = { "kdf-memory=1", "kdf-iterations=1" };

    static Credential Login(string url, string user, string password, params string[] folder)
    {
        var c = new Credential { Url = url, Username = user, Password = password };
        foreach (var f in folder) c.Folder.Add(f);
        return c;
    }

    static WriteResult WriteKeePass(string file, IReadOnlyList<Credential> creds, params string[] extra)
    {
        var provider = new KeePassProvider();
        var options = Opts(new[] { "file=" + file, "password=pw" }.Concat(FastKdfOptions).Concat(extra).ToArray());
        using var target = provider.OpenTarget(new ProviderContext(provider.TargetOptions, options));
        return target.Write(creds);
    }

    static IReadOnlyList<Credential> ReadKeePass(string file)
    {
        var provider = new KeePassProvider();
        using var source = provider.OpenSource(new ProviderContext(provider.SourceOptions, Opts("file=" + file, "password=pw")));
        return source.ReadCredentials();
    }

    [Fact]
    public void KeePass_CreatesThenMerges_SkippingDuplicates()
    {
        using var dir = new TempDir();
        var file = dir.File("out.kdbx");

        var first = WriteKeePass(file, new[] { Login("https://a.example", "alice", "1"), Login("https://b.example", "bob", "2", "Sub") });
        Assert.Equal(2, first.Added);

        var second = WriteKeePass(file, new[] { Login("https://a.example", "alice", "1"), Login("https://c.example", "carol", "3") });
        Assert.Equal(1, second.Added);
        Assert.Equal(1, second.Skipped);

        var all = ReadKeePass(file);
        Assert.Equal(3, all.Count);
        var bob = all.Single(c => c.Username == "bob");
        Assert.Equal(new[] { "Imported", "Sub" }, bob.Folder);
        Assert.Equal("b.example", bob.Title);
        Assert.Equal("2", bob.Password);
        Assert.True(File.Exists(file + ".bak"));
    }

    [Fact]
    public void KeePass_DuplicatesAdd_AndCustomGroup()
    {
        using var dir = new TempDir();
        var file = dir.File("out.kdbx");
        var creds = new[] { Login("https://a.example", "alice", "1") };
        WriteKeePass(file, creds, "group=Browsers/Firefox");
        var r = WriteKeePass(file, creds, "group=Browsers/Firefox", "duplicates=add", "backup=false");
        Assert.Equal(1, r.Added);
        Assert.False(File.Exists(file + ".bak"));
        Assert.All(ReadKeePass(file), c => Assert.Equal(new[] { "Browsers", "Firefox" }, c.Folder));
    }

    [Fact]
    public void KeePass_SourceSkipsRecycleBin()
    {
        using var dir = new TempDir();
        var file = dir.File("rb.kdbx");
        var key = new KdbxKey("pw");
        var db = KdbxDatabase.Create("rb", KdbxTests.FastKdf());
        var bin = db.RootGroup.GetOrAddGroup("Recycle Bin");
        bin.AddEntry().SetString("Title", "deleted");
        db.RootGroup.AddEntry().SetString("Title", "kept");
        db.Document.Root!.Element("Meta")!.SetElementValue("RecycleBinUUID", bin.Uuid);
        db.Save(file, key);

        Assert.Equal(new[] { "kept" }, ReadKeePass(file).Select(c => c.Title));
    }

    [Fact]
    public void KeePass_WrongPassword_IsProviderException()
    {
        using var dir = new TempDir();
        var file = dir.File("x.kdbx");
        WriteKeePass(file, new[] { Login("https://a.example", "a", "b") });
        var provider = new KeePassProvider();
        var e = Assert.Throws<ProviderException>(() =>
            provider.OpenSource(new ProviderContext(provider.SourceOptions, Opts("file=" + file, "password=nope"))));
        Assert.Contains("Wrong master password", e.Message);
    }

    [Fact]
    public void Context_RejectsUnknownOptions_AndReadsSecretsFromEnvironment()
    {
        var provider = new KeePassProvider();
        Assert.Throws<ProviderException>(() => new ProviderContext(provider.SourceOptions, Opts("file=x", "pasword=typo")));

        Environment.SetEnvironmentVariable("PWPORT_TEST_SECRET", "from-env");
        var ctx = new ProviderContext(provider.SourceOptions, Opts("file=x", "password-env=PWPORT_TEST_SECRET"));
        Assert.Equal("from-env", ctx.GetSecret("password", "unused"));
    }

    [Fact]
    public void Csv_RoundTrip()
    {
        using var dir = new TempDir();
        var file = dir.File("out.csv");
        var c = Login("https://a.example", "alice", "pa,ss\"word\nx", "Work", "Mail");
        c.Notes = " leading space";
        c.Fields["HTTP Realm"] = "realm";

        var provider = new CsvProvider();
        using (var t = provider.OpenTarget(new ProviderContext(provider.TargetOptions, Opts("file=" + file))))
            t.Write(new[] { c });

        using var s = provider.OpenSource(new ProviderContext(provider.SourceOptions, Opts("file=" + file)));
        var back = s.ReadCredentials().Single();
        Assert.Equal(c.Password, back.Password);
        Assert.Equal(c.Notes, back.Notes);
        Assert.Equal(new[] { "Work", "Mail" }, back.Folder);
        Assert.Equal("realm", back.Fields["HTTP Realm"]);
    }

    [Fact]
    public void Csv_ReadsFirefoxExportColumns()
    {
        using var dir = new TempDir();
        var file = dir.File("firefox.csv");
        File.WriteAllText(file,
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\r\n" +
            "\"https://example.com\",\"me\",\"secret\",,\"https://example.com\",\"{1}\",\"1\",\"2\",\"3\"\r\n");
        var provider = new CsvProvider();
        using var s = provider.OpenSource(new ProviderContext(provider.SourceOptions, Opts("file=" + file)));
        var c = s.ReadCredentials().Single();
        Assert.Equal("https://example.com", c.Url);
        Assert.Equal("me", c.Username);
        Assert.Equal("secret", c.Password);
        Assert.Equal("example.com", c.DisplayTitle);
    }

    [Fact]
    public void SimpleJson_ParsesLoginsShape()
    {
        var json = "{\"nextId\":3,\"logins\":[{\"id\":1,\"hostname\":\"https://x.example\",\"httpRealm\":null," +
                   "\"encryptedUsername\":\"QUJD\",\"timeCreated\":1700000000123,\"esc\":\"a\\\"b\\u00e9\\n\"}],\"ok\":true,\"f\":1.5e2}";
        var root = SimpleJson.AsObject(SimpleJson.Parse(json))!;
        var login = SimpleJson.AsObject(SimpleJson.AsArray(root["logins"])![0])!;
        Assert.Equal("https://x.example", login.GetString("hostname"));
        Assert.Null(login["httpRealm"]);
        Assert.Equal(1700000000123L, login.GetInt64("timeCreated"));
        Assert.Equal("a\"bé\n", login.GetString("esc"));
        Assert.Equal(true, root["ok"]);
        Assert.Equal(150.0, root["f"]);
        Assert.Throws<FormatException>(() => SimpleJson.Parse("{\"a\":}"));
    }

    [Fact]
    public void FirefoxProfilesIni_PrefersInstallDefault()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(Path.Combine(dir.Path, "Profiles", "abc.default"));
        Directory.CreateDirectory(Path.Combine(dir.Path, "Profiles", "xyz.default-release"));
        var ini = new[]
        {
            "[Install308046B0AF4A39CB]", "Default=Profiles/xyz.default-release", "Locked=1", "",
            "[Profile1]", "Name=default", "IsRelative=1", "Path=Profiles/abc.default", "Default=1", "",
            "[Profile0]", "Name=default-release", "IsRelative=1", "Path=Profiles/xyz.default-release", "",
            "[Profile2]", "Name=missing", "IsRelative=1", "Path=Profiles/gone", "",
            "[General]", "StartWithLastProfile=1", "Version=2",
        };
        var profiles = FirefoxProfiles.ParseProfilesIni(dir.Path, ini);
        Assert.Equal(2, profiles.Count);
        Assert.Equal("default-release", profiles.Single(p => p.IsDefault).Name);
    }
}
