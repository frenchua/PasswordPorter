using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            switch (cmd.Command)
            {
                case null:
                case "help":
                    PrintUsage(registry);
                    return ExitOk;
                case "version":
                    Console.WriteLine(typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);
                    return ExitOk;
                case "providers":
                    return Providers(registry, cmd);
                case "profiles":
                    return Profiles(registry, cmd);
                case "list":
                    return List(registry, cmd);
                case "export":
                    return Export(registry, cmd);
                default:
                    throw new UsageException($"Unknown command '{cmd.Command}'.");
            }
        }
        catch (UsageException e)
        {
            Console.Error.WriteLine("error: " + e.Message);
            Console.Error.WriteLine("Run 'pwport help' for usage.");
            return ExitUsage;
        }
        catch (ProviderException e)
        {
            Console.Error.WriteLine("error: " + e.Message);
            return ExitError;
        }
    }

    static void PrintUsage(ProviderRegistry registry)
    {
        Console.WriteLine(
@"pwport - move saved passwords between browsers and password managers

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
");
        Console.WriteLine("Providers: " + string.Join(", ", registry.Providers.Select(p => p.Info.Id)));
    }

    static int Providers(ProviderRegistry registry, CommandLine cmd)
    {
        if (cmd.Positionals.Count == 0)
        {
            foreach (var p in registry.Providers)
            {
                var caps = new List<string>();
                if (p is ICredentialSourceProvider) caps.Add("read");
                if (p is ICredentialTargetProvider) caps.Add("write");
                if (p is IProfileDiscovery) caps.Add("profiles");
                Console.WriteLine($"{p.Info.Id,-10} {p.Info.DisplayName,-18} [{string.Join(", ", caps)}]");
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
            var notes = new List<string>();
            if (o.IsRequired) notes.Add("required");
            if (o.IsSecret) notes.Add($"secret, prompted; or {o.Name}-env=VAR");
            if (o.DefaultValue != null) notes.Add("default: " + o.DefaultValue);
            Console.WriteLine($"  {o.Name,-16} {o.Description}");
            if (notes.Count > 0)
                Console.WriteLine($"  {"",-16} ({string.Join("; ", notes)})");
        }
    }

    static int Profiles(ProviderRegistry registry, CommandLine cmd)
    {
        var provider = registry.Get(cmd.RequirePositional(0, "provider"));
        if (!(provider is IProfileDiscovery discovery))
            throw new ProviderException($"'{provider.Info.Id}' does not have discoverable profiles.");
        var profiles = discovery.DiscoverProfiles();
        if (profiles.Count == 0)
            Console.WriteLine("No profiles found.");
        foreach (var p in profiles)
            Console.WriteLine($"{(p.IsDefault ? "*" : " ")} {p.Name,-24} {p.Path}");
        return ExitOk;
    }

    static int List(ProviderRegistry registry, CommandLine cmd)
    {
        var credentials = ReadSource(registry, cmd.RequirePositional(0, "source"), cmd.InOptions);
        var rows = credentials.Select(c => new[]
        {
            Truncate(c.Folder.Count > 0 ? string.Join("/", c.Folder) + "/" + c.DisplayTitle : c.DisplayTitle, 40),
            Truncate(c.Username ?? "", 30),
            Truncate(c.Url ?? "", 50),
            cmd.ShowPasswords ? c.Password ?? "" : (string.IsNullOrEmpty(c.Password) ? "" : "********"),
        }).ToList();
        PrintTable(new[] { "TITLE", "USERNAME", "URL", "PASSWORD" }, rows);
        Console.Error.WriteLine($"{credentials.Count} credential(s).");
        return ExitOk;
    }

    static int Export(ProviderRegistry registry, CommandLine cmd)
    {
        var sourceId = cmd.RequirePositional(0, "source");
        var targetId = cmd.RequirePositional(1, "target");
        if (!(registry.Get(targetId) is ICredentialTargetProvider targetProvider))
            throw new ProviderException($"'{targetId}' cannot be written to.");
        // Validate target options before prompting for anything.
        var interaction = new ConsoleInteraction();
        new ProviderContext(targetProvider.TargetOptions, cmd.OutOptions, NonInteractive.Instance);

        var credentials = ReadSource(registry, sourceId, cmd.InOptions);
        Console.Error.WriteLine($"Read {credentials.Count} credential(s) from {sourceId}.");
        if (cmd.DryRun)
        {
            Console.Error.WriteLine("Dry run: nothing written.");
            return ExitOk;
        }

        using var target = targetProvider.OpenTarget(new ProviderContext(targetProvider.TargetOptions, cmd.OutOptions, interaction));
        var result = target.Write(credentials);
        Console.Error.WriteLine($"Added {result.Added}, skipped {result.Skipped} (already present)" +
            (result.Location != null ? $" -> {result.Location}" : "") + ".");
        return ExitOk;
    }

    static IReadOnlyList<Credential> ReadSource(ProviderRegistry registry, string id, Dictionary<string, string> options)
    {
        if (!(registry.Get(id) is ICredentialSourceProvider provider))
            throw new ProviderException($"'{id}' cannot be read from.");
        var context = new ProviderContext(provider.SourceOptions, options, new ConsoleInteraction());
        using var source = provider.OpenSource(context);
        return source.ReadCredentials();
    }

    static string Truncate(string s, int max) => s.Length <= max ? s : s.Substring(0, max - 3) + "...";

    static void PrintTable(string[] headers, List<string[]> rows)
    {
        var widths = headers.Select((h, i) => Math.Max(h.Length, rows.Count == 0 ? 0 : rows.Max(r => r[i].Length))).ToArray();
        void Print(string[] cells) =>
            Console.WriteLine(string.Join("  ", cells.Select((c, i) => i == cells.Length - 1 ? c : c.PadRight(widths[i]))));
        Print(headers);
        foreach (var r in rows)
            Print(r);
    }
}

internal sealed class UsageException : Exception
{
    public UsageException(string message) : base(message) { }
}

/// <summary>Minimal parser: a command, positionals, -i/-o key=value pairs and flags.</summary>
internal sealed class CommandLine
{
    public string? Command { get; private set; }
    public List<string> Positionals { get; } = new List<string>();
    public Dictionary<string, string> InOptions { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> OutOptions { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
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
                case "-h": case "--help": case "/?":
                    cmd.Command = "help";
                    return cmd;
                case "-i": case "--in":
                    AddOption(cmd.InOptions, a, NextValue(args, ref i, a));
                    break;
                case "-o": case "--out":
                    AddOption(cmd.OutOptions, a, NextValue(args, ref i, a));
                    break;
                case "--show-passwords":
                    cmd.ShowPasswords = true;
                    break;
                case "--dry-run":
                    cmd.DryRun = true;
                    break;
                default:
                    if (a.StartsWith("-") && a != "-")
                        throw new UsageException($"Unknown flag '{a}'.");
                    if (cmd.Command == null) cmd.Command = a.ToLowerInvariant();
                    else cmd.Positionals.Add(a);
                    break;
            }
        }
        return cmd;
    }

    static string NextValue(string[] args, ref int i, string flag)
    {
        if (i + 1 >= args.Length)
            throw new UsageException($"'{flag}' needs a key=value argument.");
        return args[++i];
    }

    static void AddOption(Dictionary<string, string> target, string flag, string pair)
    {
        var eq = pair.IndexOf('=');
        if (eq <= 0)
            throw new UsageException($"'{flag} {pair}': expected key=value.");
        target[pair.Substring(0, eq).Trim()] = pair.Substring(eq + 1);
    }

    public string RequirePositional(int index, string name) =>
        index < Positionals.Count ? Positionals[index] : throw new UsageException($"Missing <{name}>.");
}
