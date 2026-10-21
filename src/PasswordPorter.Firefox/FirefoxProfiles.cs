using PasswordPorter.Providers;

namespace PasswordPorter.Firefox;

/// <summary>Finds Firefox profiles by reading profiles.ini from the usual per-user locations.</summary>
public static class FirefoxProfiles
{
    public static IReadOnlyList<ProfileInfo> Discover() =>
    [
        .. ProfileRoots()
            .Select(root => (root, ini: Path.Combine(root, "profiles.ini")))
            .Where(x => File.Exists(x.ini))
            .SelectMany(x => ParseProfilesIni(x.root, File.ReadAllLines(x.ini))),
    ];

    /// <summary>Parses profiles.ini. The [Install...] sections hold the default profile of each installation.</summary>
    internal static List<ProfileInfo> ParseProfilesIni(string root, IEnumerable<string> lines)
    {
        List<(string name, Dictionary<string, string> values)> sections = [];
        foreach (var line in lines.Select(l => l.Trim()))
        {
            switch (line)
            {
                case "" or [';' or '#', ..]:
                    break;
                case ['[', .. var name, ']']:
                    sections.Add((name, new(StringComparer.OrdinalIgnoreCase)));
                    break;
                default:
                    if (sections is [.., var section] && line.Split('=', 2) is [{ Length: > 0 } key, var value])
                        section.values[key.Trim()] = value.Trim();
                    break;
            }
        }

        var installDefaults = sections
            .Where(s => s.name.StartsWith("Install", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.values.GetValueOrDefault("Default"))
            .OfType<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        List<ProfileInfo> profiles = [];
        foreach (var (_, values) in sections.Where(s => s.name.StartsWith("Profile", StringComparison.OrdinalIgnoreCase)))
        {
            if (!values.TryGetValue("Path", out var relPath))
                continue;
            var isRelative = values.GetValueOrDefault("IsRelative", "1") == "1";
            var fullPath = isRelative ? Path.Combine(root, relPath.Replace('/', Path.DirectorySeparatorChar)) : relPath;
            if (!Directory.Exists(fullPath))
                continue;
            var isDefault = installDefaults.Count > 0
                ? installDefaults.Contains(relPath)
                : values.GetValueOrDefault("Default") == "1";
            profiles.Add(new(values.GetValueOrDefault("Name", relPath), Path.GetFullPath(fullPath), isDefault));
        }
        return profiles;
    }

    static IEnumerable<string> ProfileRoots()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsWindows())
        {
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla", "Firefox");
        }
        else if (OperatingSystem.IsMacOS())
        {
            yield return Path.Combine(home, "Library", "Application Support", "Firefox");
        }
        else
        {
            var xdgConfig = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } xdg ? xdg : Path.Combine(home, ".config");
            yield return Path.Combine(xdgConfig, "mozilla", "firefox");
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
        string Names() => profiles is [] ? "(none)" : string.Join(", ", profiles.Select(p => p.Name));

        if (string.IsNullOrEmpty(profile))
        {
            return (profiles.Where(p => p.IsDefault).ToList(), profiles) switch
            {
                ([var onlyDefault], _) => onlyDefault.Path,
                (_, [var only]) => only.Path,
                (_, []) => throw new ProviderException("No Firefox profiles were found. Pass profile=<profile folder>."),
                _ => throw new ProviderException($"Several Firefox profiles exist; choose one with profile=<name or folder>: {Names()}"),
            };
        }

        return profiles.Where(p => p.Name.Equals(profile, StringComparison.OrdinalIgnoreCase)).ToList() switch
        {
            [var match] => match.Path,
            [] => throw new ProviderException($"No Firefox profile named '{profile}' (and no such folder). Known profiles: {Names()}"),
            _ => throw new ProviderException($"Several Firefox profiles are named '{profile}'; pass the profile folder instead."),
        };
    }
}
