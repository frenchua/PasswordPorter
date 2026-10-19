using System;
using System.Collections.Generic;
using System.IO;
using PasswordPorter.Firefox.Native;
using PasswordPorter.Providers;
using PasswordPorter.Text;

namespace PasswordPorter.Firefox;

/// <summary>
/// Reads saved logins from a Firefox profile (logins.json + key4.db), decrypting them with the
/// NSS library that ships with Firefox, so every key format Firefox supports is handled.
/// </summary>
public sealed class FirefoxProvider : ICredentialSourceProvider, IProfileDiscovery
{
    public ProviderInfo Info { get; } = new ProviderInfo(
        "firefox", "Mozilla Firefox", ProviderKind.Browser,
        "Saved logins from a Firefox profile. Needs Firefox installed, with the same bitness as this program.");

    public IReadOnlyList<ProviderOption> SourceOptions { get; } = new[]
    {
        new ProviderOption("profile", "Profile name or folder. Defaults to the default profile."),
        new ProviderOption("password", "Primary password, if the profile has one.", secret: true),
        new ProviderOption("nss-dir", "Folder containing Firefox's NSS library. Found automatically if Firefox is installed normally."),
    };

    public IReadOnlyList<ProfileInfo> DiscoverProfiles() => FirefoxProfiles.Discover();

    public ICredentialSource OpenSource(ProviderContext context)
    {
        var profileDir = FirefoxProfiles.Resolve(context.Get("profile"));
        var nssPath = NssLocator.Find(context.Get("nss-dir"));
        return new FirefoxSource(context, profileDir, nssPath);
    }

    internal sealed class FirefoxSource : ICredentialSource
    {
        readonly ProviderContext context;
        readonly string profileDir;
        readonly string nssPath;

        public FirefoxSource(ProviderContext context, string profileDir, string nssPath)
        {
            this.context = context;
            this.profileDir = profileDir;
            this.nssPath = nssPath;
        }

        public IReadOnlyList<Credential> ReadCredentials()
        {
            var loginsFile = Path.Combine(profileDir, "logins.json");
            if (!File.Exists(loginsFile))
            {
                if (File.Exists(Path.Combine(profileDir, "signons.sqlite")))
                    throw new ProviderException("This profile uses signons.sqlite (Firefox 31 or older), which is not supported.");
                context.Interaction.Warn($"No logins.json in '{profileDir}'; the profile has no saved logins.");
                return Array.Empty<Credential>();
            }
            if (!File.Exists(Path.Combine(profileDir, "key4.db")))
                throw new ProviderException($"'{profileDir}' has logins.json but no key4.db, so the logins cannot be decrypted.");

            var logins = ParseLogins(File.ReadAllText(loginsFile));

            NssLibrary library;
            try
            {
                library = NssLibrary.Load(nssPath);
            }
            catch (Exception e) when (e is DllNotFoundException || e is BadImageFormatException || e is EntryPointNotFoundException || e is PlatformNotSupportedException)
            {
                throw new ProviderException(e.Message, e);
            }

            NssSession session;
            try
            {
                session = library.OpenSession(profileDir);
            }
            catch (NssException e)
            {
                throw new ProviderException($"Could not open the Firefox key database in '{profileDir}': {e.Message}", e);
            }

            using (session)
            {
                Unlock(session);

                var result = new List<Credential>(logins.Count);
                int failures = 0;
                foreach (var login in logins)
                {
                    try
                    {
                        result.Add(ToCredential(login, session));
                    }
                    catch (Exception e) when (e is NssException || e is FormatException)
                    {
                        failures++;
                        context.Interaction.Warn($"Skipped the login for {login.GetString("hostname")}: {e.Message}");
                    }
                }
                if (failures > 0)
                    context.Interaction.Warn($"{failures} of {logins.Count} logins could not be decrypted.");
                return result;
            }
        }

        void Unlock(NssSession session)
        {
            if (!session.NeedsPassword)
                return;

            var password = context.GetSecret("password", "Firefox primary password: ");
            if (password == null)
                throw new ProviderException("This Firefox profile is protected by a primary password. Supply it with password=... or password-env=VAR.");
            if (!session.TryUnlock(password))
                throw new ProviderException("Wrong Firefox primary password.");
        }

        internal static List<Dictionary<string, object?>> ParseLogins(string json)
        {
            object? root;
            try
            {
                root = SimpleJson.Parse(json);
            }
            catch (FormatException e)
            {
                throw new ProviderException("logins.json is not valid JSON: " + e.Message, e);
            }

            var result = new List<Dictionary<string, object?>>();
            var logins = SimpleJson.AsArray(SimpleJson.AsObject(root)?.TryGetValue("logins", out var l) == true ? l : null);
            if (logins == null)
                return result;
            foreach (var item in logins)
                if (SimpleJson.AsObject(item) is { } obj)
                    result.Add(obj);
            return result;
        }

        static Credential ToCredential(Dictionary<string, object?> login, NssSession session)
        {
            var hostname = login.GetString("hostname");
            var credential = new Credential
            {
                Title = Uri.TryCreate(hostname, UriKind.Absolute, out var uri) && uri.Host.Length > 0 ? uri.Host : hostname,
                Url = hostname,
                Username = Decrypt(session, login.GetString("encryptedUsername")),
                Password = Decrypt(session, login.GetString("encryptedPassword")),
                Created = FromUnixMs(login.GetInt64("timeCreated")),
                Modified = FromUnixMs(login.GetInt64("timePasswordChanged")),
                LastUsed = FromUnixMs(login.GetInt64("timeLastUsed")),
            };

            // Basic-auth logins have a realm instead of a form; keep it so nothing is lost.
            var realm = login.GetString("httpRealm");
            if (!string.IsNullOrEmpty(realm))
                credential.Fields["HTTP Realm"] = realm!;
            return credential;
        }

        // Firefox stores 0 for "never", which should stay unknown rather than become 1970.
        static DateTime? FromUnixMs(long? ms) =>
            ms > 0 ? DateTimeOffset.FromUnixTimeMilliseconds(ms.Value).UtcDateTime : (DateTime?)null;

        static string? Decrypt(NssSession session, string? base64) =>
            string.IsNullOrEmpty(base64) ? null : session.DecryptString(base64!);

        public void Dispose() { }
    }
}
