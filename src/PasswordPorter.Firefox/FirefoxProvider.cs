using PasswordPorter.Firefox.Native;
using PasswordPorter.Providers;

namespace PasswordPorter.Firefox;

/// <summary>
/// Reads saved logins from a Firefox profile (logins.json + key4.db), decrypting them with the
/// NSS library that ships with Firefox, so every key format Firefox supports is handled.
/// </summary>
public sealed class FirefoxProvider : ICredentialSourceProvider, IProfileDiscovery
{
    public ProviderInfo Info { get; } = new(
        "firefox", "Mozilla Firefox", ProviderKind.Browser,
        "Saved logins from a Firefox profile. Needs Firefox installed, with the same bitness as this program.");

    public IReadOnlyList<ProviderOption> SourceOptions { get; } =
    [
        new("profile", "Profile name or folder. Defaults to the default profile."),
        new("password", "Primary password, if the profile has one.", IsSecret: true),
        new("nss-dir", "Folder containing Firefox's NSS library. Found automatically if Firefox is installed normally."),
    ];

    public IReadOnlyList<ProfileInfo> DiscoverProfiles() => FirefoxProfiles.Discover();

    public ICredentialSource OpenSource(ProviderContext context)
    {
        var profileDir = FirefoxProfiles.Resolve(context.Get("profile"));
        var nssPath = NssLocator.Find(context.Get("nss-dir"));
        return new FirefoxSource(context, profileDir, nssPath);
    }

    sealed class FirefoxSource(ProviderContext context, string profileDir, string nssPath) : ICredentialSource
    {
        public IReadOnlyList<Credential> ReadCredentials()
        {
            var loginsFile = Path.Combine(profileDir, "logins.json");
            if (!File.Exists(loginsFile))
            {
                if (File.Exists(Path.Combine(profileDir, "signons.sqlite")))
                    throw new ProviderException("This profile uses signons.sqlite (Firefox 31 or older), which is not supported.");
                context.Interaction.Warn($"No logins.json in '{profileDir}'; the profile has no saved logins.");
                return [];
            }
            if (!File.Exists(Path.Combine(profileDir, "key4.db")))
                throw new ProviderException($"'{profileDir}' has logins.json but no key4.db, so the logins cannot be decrypted.");

            var logins = FirefoxLogins.Parse(File.ReadAllText(loginsFile));

            NssLibrary library;
            try
            {
                library = NssLibrary.Load(nssPath);
            }
            catch (Exception e) when (e is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException)
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
                    catch (Exception e) when (e is NssException or FormatException)
                    {
                        failures++;
                        context.Interaction.Warn($"Skipped the login for {login.Hostname}: {e.Message}");
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

            var password = context.GetSecret("password", "Firefox primary password: ")
                ?? throw new ProviderException("This Firefox profile is protected by a primary password. Supply it with password=... or password-env=VAR.");
            if (!session.TryUnlock(password))
                throw new ProviderException("Wrong Firefox primary password.");
        }

        static Credential ToCredential(FirefoxLogin login, NssSession session)
        {
            var hostname = login.Hostname;
            var credential = new Credential
            {
                Title = Uri.TryCreate(hostname, UriKind.Absolute, out var uri) && uri.Host.Length > 0 ? uri.Host : hostname,
                Url = hostname,
                Username = Decrypt(session, login.EncryptedUsername),
                Password = Decrypt(session, login.EncryptedPassword),
                Created = FromUnixMs(login.TimeCreated),
                Modified = FromUnixMs(login.TimePasswordChanged),
                LastUsed = FromUnixMs(login.TimeLastUsed),
            };

            // Basic-auth logins have a realm instead of a form; keep it so nothing is lost.
            if (!string.IsNullOrEmpty(login.HttpRealm))
                credential.Fields["HTTP Realm"] = login.HttpRealm;
            return credential;
        }

        // Firefox stores 0 for "never", which should stay unknown rather than become 1970.
        static DateTime? FromUnixMs(long? ms) =>
            ms > 0 ? DateTimeOffset.FromUnixTimeMilliseconds(ms.Value).UtcDateTime : null;

        static string? Decrypt(NssSession session, string? base64) =>
            string.IsNullOrEmpty(base64) ? null : session.DecryptString(base64);

        public void Dispose() { }
    }
}
