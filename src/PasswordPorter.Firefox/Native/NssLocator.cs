using System.Runtime.Versioning;
using Microsoft.Win32;
using PasswordPorter.Providers;

namespace PasswordPorter.Firefox.Native;

/// <summary>Finds the NSS shared library that belongs to an installed Firefox.</summary>
internal static class NssLocator
{
    public static string LibraryFileName =>
        OperatingSystem.IsWindows() ? "nss3.dll"
        : OperatingSystem.IsMacOS() ? "libnss3.dylib"
        : "libnss3.so";

    /// <summary>Returns the full path of the NSS library, or throws with the locations that were tried.</summary>
    public static string Find(string? explicitDirectory)
    {
        if (!string.IsNullOrEmpty(explicitDirectory))
        {
            var candidate = File.Exists(explicitDirectory) ? explicitDirectory : Path.Combine(explicitDirectory, LibraryFileName);
            if (!File.Exists(candidate))
                throw new ProviderException($"'{LibraryFileName}' was not found in '{explicitDirectory}'.");
            return Path.GetFullPath(candidate);
        }

        List<string> tried = [];
        foreach (var dir in CandidateDirectories())
        {
            if (string.IsNullOrEmpty(dir))
                continue;
            var candidate = Path.Combine(dir, LibraryFileName);
            if (tried.Contains(candidate))
                continue;
            tried.Add(candidate);
            if (File.Exists(candidate))
                return candidate;
        }

        throw new ProviderException(
            "Could not find Firefox's NSS library. Pass nss-dir=<Firefox install folder>. Looked in:" +
            Environment.NewLine + "  " + string.Join(Environment.NewLine + "  ", tried));
    }

    static IEnumerable<string?> CandidateDirectories()
    {
        if (OperatingSystem.IsWindows())
        {
            foreach (var dir in RegistryInstallDirectories())
                yield return dir;

            string?[] roots =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetEnvironmentVariable("ProgramW6432"),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            ];
            foreach (var root in roots)
            {
                if (string.IsNullOrEmpty(root))
                    continue;
                foreach (var name in (string[])["Mozilla Firefox", "Firefox Developer Edition", "Firefox Nightly", "Mozilla Firefox ESR"])
                    yield return Path.Combine(root, name);
            }
        }
        else if (OperatingSystem.IsMacOS())
        {
            yield return "/Applications/Firefox.app/Contents/MacOS";
            yield return "/Applications/Firefox Developer Edition.app/Contents/MacOS";
            yield return "/Applications/Firefox Nightly.app/Contents/MacOS";
            yield return "/opt/homebrew/opt/nss/lib";
            yield return "/usr/local/opt/nss/lib";
        }
        else
        {
            yield return "/usr/lib/firefox";
            yield return "/usr/lib64/firefox";
            yield return "/opt/firefox";
            yield return "/usr/lib/x86_64-linux-gnu";
            yield return "/usr/lib/aarch64-linux-gnu";
            yield return "/usr/lib64";
            yield return "/usr/lib";
            yield return "/snap/firefox/current/usr/lib/firefox";
        }
    }

    [SupportedOSPlatform("windows")]
    static List<string> RegistryInstallDirectories()
    {
        List<string> result = [];
        try
        {
            foreach (var hive in (RegistryKey[])[Registry.LocalMachine, Registry.CurrentUser])
            {
                using var products = hive.OpenSubKey(@"SOFTWARE\Mozilla\Mozilla Firefox");
                if (products is null)
                    continue;
                foreach (var version in products.GetSubKeyNames())
                {
                    using var main = products.OpenSubKey(version + @"\Main");
                    if (main?.GetValue("Install Directory") is string dir)
                        result.Add(dir);
                }
            }
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Registry not readable; fall back to the well-known folders.
        }
        return result;
    }
}
