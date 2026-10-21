using System.Reflection;
using PasswordPorter.Firefox;
using PasswordPorter.KeePass;
using PasswordPorter.Providers;
using PasswordPorter.Providers.Csv;

namespace PasswordPorter.Cli;

internal static class Program
{
    const int ExitOk = 0, ExitError = 1, ExitUsage = 2;

    /// <summary>Every provider the CLI offers. Add new browsers and password managers here.</summary>
    static ProviderRegistry CreateRegistry() => new ProviderRegistry()
        .Register(new FirefoxProvider())
        .Register(new KeePassProvider())
        .Register(new CsvProvider());

    static int Main(string[] args)
    {
        var registry = CreateRegistry();
        try
        {
            var cmd = CommandLine.Parse(args);
            return cmd.Command switch
            {
                null or "help" => PrintUsage(registry),
                "version" => PrintVersion(),
                "providers" => Providers(registry, cmd),
                "profiles" => Profiles(registry, cmd),
                "list" => List(registry, cmd),
                "export" => Export(registry, cmd),
                _ => throw new UsageException($"Unknown command '{cmd.Command}'."),
            };
        }
        catch (UsageException e)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            Console.Error.WriteLine("Run 'pwport help' for usage.");
            return ExitUsage;
        }
        catch (ProviderException e)
        {
            Console.Error.WriteLine($"error: {e.Message}");
            return ExitError;
        }
    }

    static int PrintUsage(ProviderRegistry registry)
    {
        Console.WriteLine("""
            pwport - move saved passwords between browsers and password managers

            Usage:
              pwport providers [<provider>]          List providers, or show one provider's options
              pwport profiles <provider>             List the profiles a provider can find on this machine
              pwport list <source> [-i k=v]...       Show credentials (passwords hidden unless --show-passwords)
              pwport export <source> <target> [-i k=v]... [-o k=v]... [--dry-run]
                                                     Copy credentials from <source> into <target>

            Options:
              -i, --in key=value     Option for the source provider (repeatable)
              -o, --out key=value    Option for the target provider (repeatable)
              --show-passwords       'list' only: print passwords in clear text
              --dry-run              'export' only: read the source and report, but write nothing

            Secrets (master passwords) are prompted for. To script, use <name>-env=VARIABLE to read one
            from an environment variable; passing password=... works but ends up in shell history.

            Examples:
              pwport profiles firefox
              pwport export firefox keepass -o file=Passwords.kdbx
              pwport export firefox keepass -i profile=default-release -o file=Passwords.kdbx -o group=Browsers/Firefox
              pwport export keepass csv -i file=Passwords.kdbx -o file=-

            """);
        Console.WriteLine($"Providers: {string.Join(", ", registry.Providers.Select(p => p.Info.Id))}");
        return ExitOk;
    }

    static int PrintVersion()
    {
        Console.WriteLine(typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);
        return ExitOk;
    }

    static int Providers(ProviderRegistry registry, CommandLine cmd)
    {
        if (cmd.Positionals is [])
        {
            foreach (var p in registry.Providers)
            {
                string?[] caps =
                [
                    p is ICredentialSourceProvider ? "read" : null,
                    p is ICredentialTargetProvider ? "write" : null,
                    p is IProfileDiscovery ? "profiles" : null,
                ];
                Console.WriteLine($"{p.Info.Id,-10} {p.Info.DisplayName,-18} [{string.Join(", ", caps.OfType<string>())}]");
                Console.WriteLine($"{"",-10} {p.Info.Description}");
            }
            return ExitOk;
        }

        var provider = registry.Get(cmd.Positionals[0]);
        Console.WriteLine($"{provider.Info.DisplayName} ({provider.Info.Id})");
        Console.WriteLine(provider.Info.Description);
        if (provider is ICredentialSourceProvider source)
            PrintOptions("As a source (-i):", source.SourceOptions);
        if (provider is ICredentialTargetProvider target)
            PrintOptions("As a target (-o):", target.TargetOptions);
        return ExitOk;
    }

    static void PrintOptions(string heading, IReadOnlyList<ProviderOption> options)
    {
        Console.WriteLine();
        Console.WriteLine(heading);
        foreach (var o in options)
        {
            string?[] notes =
            [
                o.IsRequired ? "required" : null,
                o.IsSecret ? $"secret, prompted; or {o.Name}-env=VAR" : null,
                o.DefaultValue is { } d ? $"default: {d}" : null,
            ];
            Console.WriteLine($"  {o.Name,-16} {o.Description}");
            if (notes.Any(n => n is not null))
                Console.WriteLine($"  {"",-16} ({string.Join("; ", notes.OfType<string>())})");
        }
    }

    static int Profiles(ProviderRegistry registry, CommandLine cmd)
    {
        var provider = registry.Get(cmd.RequirePositional(0, "provider"));
        if (provider is not IProfileDiscovery discovery)
            throw new ProviderException($"'{provider.Info.Id}' does not have discoverable profiles.");
        var profiles = discovery.DiscoverProfiles();
        if (profiles is [])
            Console.WriteLine("No profiles found.");
        foreach (var p in profiles)
            Console.WriteLine($"{(p.IsDefault ? "*" : " ")} {p.Name,-24} {p.Path}");
        return ExitOk;
    }

    static int List(ProviderRegistry registry, CommandLine cmd)
    {
        var credentials = ReadSource(registry, cmd.RequirePositional(0, "source"), cmd.InOptions);
        var rows = credentials.Select(string[] (c) =>
        [
            Truncate(c.Folder.Count > 0 ? $"{string.Join("/", c.Folder)}/{c.DisplayTitle}" : c.DisplayTitle, 40),
            Truncate(c.Username ?? "", 30),
            Truncate(c.Url ?? "", 50),
            cmd.ShowPasswords ? c.Password ?? "" : string.IsNullOrEmpty(c.Password) ? "" : "********",
        ]).ToList();
        PrintTable(["TITLE", "USERNAME", "URL", "PASSWORD"], rows);
        Console.Error.WriteLine($"{credentials.Count} credential(s).");
        return ExitOk;
    }

    static int Export(ProviderRegistry registry, CommandLine cmd)
    {
        var sourceId = cmd.RequirePositional(0, "source");
        var targetId = cmd.RequirePositional(1, "target");
        if (registry.Get(targetId) is not ICredentialTargetProvider targetProvider)
            throw new ProviderException($"'{targetId}' cannot be written to.");
        // Validate target options before prompting for anything.
        _ = new ProviderContext(targetProvider.TargetOptions, cmd.OutOptions, NonInteractive.Instance);

        var credentials = ReadSource(registry, sourceId, cmd.InOptions);
        Console.Error.WriteLine($"Read {credentials.Count} credential(s) from {sourceId}.");
        if (cmd.DryRun)
        {
            Console.Error.WriteLine("Dry run: nothing written.");
            return ExitOk;
        }

        using var target = targetProvider.OpenTarget(new ProviderContext(targetProvider.TargetOptions, cmd.OutOptions, new ConsoleInteraction()));
        var result = target.Write(credentials);
        var location = result.Location is { } l ? $" -> {l}" : "";
        Console.Error.WriteLine($"Added {result.Added}, skipped {result.Skipped} (already present){location}.");
        return ExitOk;
    }

    static IReadOnlyList<Credential> ReadSource(ProviderRegistry registry, string id, Dictionary<string, string> options)
    {
        if (registry.Get(id) is not ICredentialSourceProvider provider)
            throw new ProviderException($"'{id}' cannot be read from.");
        using var source = provider.OpenSource(new ProviderContext(provider.SourceOptions, options, new ConsoleInteraction()));
        return source.ReadCredentials();
    }

    static string Truncate(string s, int max) => s.Length <= max ? s : $"{s[..(max - 3)]}...";

    static void PrintTable(string[] headers, List<string[]> rows)
    {
        var widths = headers.Select((h, i) => rows.Select(r => r[i].Length).Prepend(h.Length).Max()).ToArray();
        void Print(string[] cells) =>
            Console.WriteLine(string.Join("  ", cells.Select((c, i) => i == cells.Length - 1 ? c : c.PadRight(widths[i]))));
        Print(headers);
        foreach (var r in rows)
            Print(r);
    }
}

internal sealed class UsageException(string message) : Exception(message);

/// <summary>Minimal parser: a command, positionals, -i/-o key=value pairs and flags.</summary>
internal sealed class CommandLine
{
    public string? Command { get; private set; }
    public List<string> Positionals { get; } = [];
    public Dictionary<string, string> InOptions { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> OutOptions { get; } = new(StringComparer.OrdinalIgnoreCase);
    public bool ShowPasswords { get; private set; }
    public bool DryRun { get; private set; }

    public static CommandLine Parse(string[] args)
    {
        var cmd = new CommandLine();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "-h" or "--help" or "/?":
                    cmd.Command = "help";
                    return cmd;
                case "-i" or "--in":
                    AddOption(cmd.InOptions, a, NextValue(args, ref i, a));
                    break;
                case "-o" or "--out":
                    AddOption(cmd.OutOptions, a, NextValue(args, ref i, a));
                    break;
                case "--show-passwords":
                    cmd.ShowPasswords = true;
                    break;
                case "--dry-run":
                    cmd.DryRun = true;
                    break;
                case ['-', _, ..]:
                    throw new UsageException($"Unknown flag '{a}'.");
                default:
                    if (cmd.Command is null) cmd.Command = a.ToLowerInvariant();
                    else cmd.Positionals.Add(a);
                    break;
            }
        }
        return cmd;
    }

    static string NextValue(string[] args, ref int i, string flag) =>
        i + 1 < args.Length ? args[++i] : throw new UsageException($"'{flag}' needs a key=value argument.");

    static void AddOption(Dictionary<string, string> target, string flag, string pair)
    {
        if (pair.Split('=', 2) is not [var key, var value] || key.Trim() is not { Length: > 0 } name)
            throw new UsageException($"'{flag} {pair}': expected key=value.");
        target[name] = value;
    }

    public string RequirePositional(int index, string name) =>
        index < Positionals.Count ? Positionals[index] : throw new UsageException($"Missing <{name}>.");
}
