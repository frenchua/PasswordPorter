using System.Collections.Generic;
using System.IO;
using System.Linq;
using PasswordPorter.Firefox;
using PasswordPorter.Firefox.Native;
using PasswordPorter.Providers;
using Xunit;
using Xunit.Abstractions;

namespace PasswordPorter.Tests;

/// <summary>
/// End-to-end tests against the real NSS library of an installed Firefox, using a throwaway profile
/// (never the user's own). They do nothing when Firefox is not installed.
/// </summary>
[Collection("NSS")] // NSS is process-global: never run these in parallel
public class FirefoxNssTests
{
    readonly ITestOutputHelper output;

    public FirefoxNssTests(ITestOutputHelper output) { this.output = output; }

    string? FindNss()
    {
        try { return NssLocator.Find(null); }
        catch (ProviderException)
        {
            output.WriteLine("Firefox/NSS not found; skipping.");
            return null;
        }
    }

    /// <summary>Creates a fresh NSS key database and a logins.json encrypted with it.</summary>
    static void CreateProfile(string nssPath, string dir, string primaryPassword, params (string host, string user, string pass)[] logins)
    {
        var lib = NssLibrary.Load(nssPath);
        var entries = new List<string>();
        using (var session = lib.OpenSession(dir, readWrite: true))
        {
            session.Initialize(primaryPassword);
            if (session.NeedsPassword)
                Assert.True(session.TryUnlock(primaryPassword));
            int id = 1;
            foreach (var (host, user, pass) in logins)
            {
                entries.Add("{\"id\":" + id++ + ",\"hostname\":\"" + host + "\",\"httpRealm\":null,\"formSubmitURL\":\"" + host + "\"," +
                    "\"usernameField\":\"u\",\"passwordField\":\"p\"," +
                    "\"encryptedUsername\":\"" + session.EncryptString(user) + "\"," +
                    "\"encryptedPassword\":\"" + session.EncryptString(pass) + "\"," +
                    "\"guid\":\"{" + System.Guid.NewGuid() + "}\",\"encType\":1,\"timeCreated\":1700000000000," +
                    "\"timeLastUsed\":1700000001000,\"timePasswordChanged\":1700000002000,\"timesUsed\":1}");
            }
        }
        File.WriteAllText(Path.Combine(dir, "logins.json"),
            "{\"nextId\":" + (logins.Length + 1) + ",\"logins\":[" + string.Join(",", entries) + "],\"version\":3}");
    }

    static IReadOnlyList<Credential> Read(string profile, string nssPath, string? password)
    {
        var provider = new FirefoxProvider();
        var options = new Dictionary<string, string> { ["profile"] = profile, ["nss-dir"] = Path.GetDirectoryName(nssPath)! };
        if (password != null) options["password"] = password;
        using var source = provider.OpenSource(new ProviderContext(provider.SourceOptions, options));
        return source.ReadCredentials();
    }

    [Fact]
    public void ReadsLogins_WithoutPrimaryPassword()
    {
        var nss = FindNss();
        if (nss == null) return;
        using var dir = new TempDir();
        CreateProfile(nss, dir.Path, "", ("https://example.com", "alice", "s3cret ☃"), ("https://other.example:8443", "bob", "x"));

        var creds = Read(dir.Path, nss, null);
        Assert.Equal(2, creds.Count);
        var alice = creds.Single(c => c.Username == "alice");
        Assert.Equal("s3cret ☃", alice.Password);
        Assert.Equal("example.com", alice.Title);
        Assert.Equal("https://example.com", alice.Url);
        Assert.Equal(new System.DateTime(2023, 11, 14, 22, 13, 20, System.DateTimeKind.Utc), alice.Created);
    }

    [Fact]
    public void PrimaryPassword_RequiredAndChecked()
    {
        var nss = FindNss();
        if (nss == null) return;
        using var dir = new TempDir();
        CreateProfile(nss, dir.Path, "primary-pw", ("https://example.com", "carol", "pw1"));

        Assert.Contains("primary password", Assert.Throws<ProviderException>(() => Read(dir.Path, nss, null)).Message);
        Assert.Contains("Wrong", Assert.Throws<ProviderException>(() => Read(dir.Path, nss, "nope")).Message);
        Assert.Equal("pw1", Read(dir.Path, nss, "primary-pw").Single().Password);
    }
}
