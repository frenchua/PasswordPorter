using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using PasswordPorter.Providers;

namespace PasswordPorter.Firefox;

/// <summary>Finds Firefox profiles by reading profiles.ini from the usual per-user locations.</summary>
public static class FirefoxProfiles
{
    public static IReadOnlyList<ProfileInfo> Discover()
    {
        var result = new List<ProfileInfo>();
        foreach (var root in ProfileRoots())
        {
            var ini = Path.Combine(root, "profiles.ini");
            if (File.Exists(ini))
                result.AddRange(ParseProfilesIni(root, File.ReadAllLines(ini)));
        }
        return result;
    }

    /// <summary>Parses profiles.ini. The [Install...] sections hold the default profile of each installation.</summary>
    internal static List<ProfileInfo> ParseProfilesIni(string root, IEnumerable<string> lines)
    {
        var sections = new List<KeyValuePair<string, Dictionary<string, string>>>();
        Dictionary<string, string>? current = null;
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith(";") || line.StartsWith("#"))
                continue;
            if (line.StartsWith("[") && line.EndsWith("]"))
            {
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                sections.Add(new KeyValuePair<string, Dictionary<string, string>>(line.Substring(1, line.Length - 2), current));
                continue;
            }
            var eq = line.IndexOf('=');
            if (current != null && eq > 0)
                current[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
        }

        var installDefaults = new HashSet<string>(
            sections.Where(s => s.Key.StartsWith("Install", StringComparison.OrdinalIgnoreCase))
                    .Select(s => s.Value.TryGetValue("Default", out var d) ? d : null)
                    .Where(d => d != null)!,
            StringComparer.OrdinalIgnoreCase);

        var profiles = new List<ProfileInfo>();
        foreach (var section in sections.Where(s => s.Key.StartsWith("Profile", StringComparison.OrdinalIgnoreCase)))
        {
            var values = section.Value;
            if (!values.TryGetValue("Path", out var relPath))
                continue;
            bool isRelative = !values.TryGetValue("IsRelative", out var r) || r == "1";
            var fullPath = isRelative ? Path.Combine(root, relPath.Replace('/', Path.DirectorySeparatorChar)) : relPath;
            if (!Directory.Exists(fullPath))
                continue;
            var name = values.TryGetValue("Name", out var n) ? n : relPath;
            bool isDefault = installDefaults.Count > 0
                ? installDefaults.Contains(relPath)
                : values.TryGetValue("Default", out var def) && def == "1";
            profiles.Add(new ProfileInfo(name, Path.GetFullPath(fullPath), isDefault));
        }
        return profiles;
    }

    static IEnumerable<string> ProfileRoots()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla", "Firefox");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            yield return Path.Combine(home, "Library", "Application Support", "Firefox");
        }
        else
        {
            var xdgConfig = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
            yield return Path.Combine(string.IsNullOrEmpty(xdgConfig) ? Path.Combine(home, ".config") : xdgConfig!, "mozilla", "firefox");
            yield return Path.Combine(home, ".mozilla", "firefox");
            yield return Path.Combine(home, "snap", "firefox", "common", ".mozilla", "firefox");
            yield return Path.Combine(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox");
        }
    }

    /// <summary>
    /// Resolves the <c>profile</c> option: a profile name, a profile directory, or (when empty) the default profile.
    /// </summary>
    public static string Resolve(string? profile)
    {
        if (!string.IsNullOrEmpty(profile) && Directory.Exists(profile))
            return Path.GetFullPath(profile);

        var profiles = Discover();
        if (string.IsNullOrEmpty(profile))
        {
            var defaults = profiles.Where(p => p.IsDefault).ToList();
            if (defaults.Count == 1) return defaults[0].Path;
            if (profiles.Count == 1) return profiles[0].Path;
            if (profiles.Count == 0)
                throw new ProviderException("No Firefox profiles were found. Pass profile=<profile folder>.");
            throw new ProviderException("Several Firefox profiles exist; choose one with profile=<name or folder>: " +
                string.Join(", ", profiles.Select(p => p.Name)));
        }

        var match = profiles.Where(p => string.Equals(p.Name, profile, StringComparison.OrdinalIgnoreCase)).ToList();
        if (match.Count == 1)
            return match[0].Path;
        if (match.Count > 1)
            throw new ProviderException($"Several Firefox profiles are named '{profile}'; pass the profile folder instead.");
        throw new ProviderException($"No Firefox profile named '{profile}' (and no such folder). Known profiles: " +
            (profiles.Count == 0 ? "(none)" : string.Join(", ", profiles.Select(p => p.Name))));
    }
}
