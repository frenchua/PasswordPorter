using PasswordPorter.KeePass.Kdbx;
using PasswordPorter.Providers;

namespace PasswordPorter.KeePass;

/// <summary>
/// KeePass 2.x / KeePassXC databases. As a target it creates the file if needed, or merges into an
/// existing one without disturbing anything already there.
/// </summary>
public sealed class KeePassProvider : ICredentialSourceProvider, ICredentialTargetProvider
{
    public ProviderInfo Info { get; } = new(
        "keepass", "KeePass (KDBX)", ProviderKind.PasswordManager,
        "KeePass 2.x / KeePassXC database. Reads KDBX 3.1 and 4.x; adds to existing databases or creates KDBX 4 ones.");

    public IReadOnlyList<ProviderOption> SourceOptions { get; } =
    [
        new("file", "The .kdbx file.", IsRequired: true),
        new("password", "Master password.", IsSecret: true),
        new("keyfile", "Key file, if the database uses one."),
    ];

    public IReadOnlyList<ProviderOption> TargetOptions { get; } =
    [
        new("file", "The .kdbx file. Created if it does not exist, otherwise added to.", IsRequired: true),
        new("password", "Master password.", IsSecret: true),
        new("keyfile", "Key file, if the database uses (or should use) one."),
        new("group", "Group to put imported entries in ('/' separates levels; empty = top level).", DefaultValue: "Imported"),
        new("duplicates", "skip: don't add entries whose URL, username and password already exist anywhere in the database; add: add them anyway.", DefaultValue: "skip"),
        new("backup", "Keep the previous version of an existing database as <file>.bak.", DefaultValue: "true"),
        new("kdf", "New databases only: argon2id, argon2d or aes.", DefaultValue: "argon2id"),
        new("kdf-iterations", "New databases only: Argon2 passes (or AES-KDF rounds)."),
        new("kdf-memory", "New databases only: Argon2 memory in MiB.", DefaultValue: "64"),
        new("kdf-parallelism", "New databases only: Argon2 parallelism.", DefaultValue: "2"),
    ];

    public ICredentialSource OpenSource(ProviderContext context)
    {
        var file = context.GetRequired("file");
        if (!File.Exists(file))
            throw new ProviderException($"File not found: {file}");
        return new Source(Open(file, GetKey(context, file, isNew: false)));
    }

    public ICredentialTarget OpenTarget(ProviderContext context)
    {
        var file = context.GetRequired("file");
        var skipDuplicates = (context.Get("duplicates") ?? "skip").ToLowerInvariant() switch
        {
            "skip" => true,
            "add" => false,
            _ => throw new ProviderException("Option 'duplicates' must be 'skip' or 'add'."),
        };

        var isNew = !File.Exists(file);
        var kdf = isNew ? GetKdfSettings(context) : null;
        var key = GetKey(context, file, isNew);
        var db = isNew ? KdbxDatabase.Create(Path.GetFileNameWithoutExtension(file), kdf) : Open(file, key);

        var group = (context.Get("group") ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries);
        return new Target(db, file, key, group, skipDuplicates, context.GetBool("backup", true));
    }

    static KdbxDatabase Open(string file, KdbxKey key)
    {
        try
        {
            return KdbxDatabase.Load(file, key);
        }
        catch (KdbxInvalidKeyException)
        {
            throw new ProviderException($"Wrong master password or key file for '{file}'.");
        }
        catch (KdbxFormatException e)
        {
            throw new ProviderException($"Cannot read '{file}': {e.Message}", e);
        }
    }

    static KdbxKey GetKey(ProviderContext context, string file, bool isNew)
    {
        var keyFile = context.Get("keyfile");
        var hasKeyFile = !string.IsNullOrEmpty(keyFile);
        if (hasKeyFile && !File.Exists(keyFile))
            throw new ProviderException($"Key file not found: {keyFile}");

        var name = Path.GetFileName(file);
        var password = context.GetSecret("password", isNew ? $"New master password for {name}: " : $"Master password for {name}: ", confirm: isNew);

        // With a key file, an empty password means "key file only", as in KeePass.
        if (hasKeyFile && string.IsNullOrEmpty(password))
            password = null;
        return (password, hasKeyFile, isNew) switch
        {
            (null, false, _) => throw new ProviderException("A master password (password=..., password-env=VAR or the prompt) or keyfile=... is required."),
            ("", _, true) => throw new ProviderException("Refusing to create a database with an empty master password."),
            _ => new KdbxKey(password, keyFile),
        };
    }

    static KdbxKdfSettings GetKdfSettings(ProviderContext context)
    {
        var algorithm = (context.Get("kdf") ?? "argon2id").ToLowerInvariant() switch
        {
            "argon2id" => KdbxKdfAlgorithm.Argon2id,
            "argon2d" => KdbxKdfAlgorithm.Argon2d,
            "aes" or "aes-kdf" => KdbxKdfAlgorithm.AesKdf,
            _ => throw new ProviderException("Option 'kdf' must be argon2id, argon2d or aes."),
        };

        var defaults = new KdbxKdfSettings();
        var defaultIterations = algorithm == KdbxKdfAlgorithm.AesKdf ? 2_000_000L : (long)defaults.Iterations;
        var iterations = context.GetInt64("kdf-iterations", defaultIterations);
        var memory = context.GetInt64("kdf-memory", 64);
        var parallelism = context.GetInt64("kdf-parallelism", 2);
        if (iterations < 1 || memory is < 1 or > 4096 || parallelism is < 1 or > 64)
            throw new ProviderException("KDF settings out of range (iterations >= 1, memory 1-4096 MiB, parallelism 1-64).");

        return new KdbxKdfSettings
        {
            Algorithm = algorithm,
            Iterations = (ulong)iterations,
            MemoryBytes = (ulong)memory * 1024 * 1024,
            Parallelism = (uint)parallelism,
        };
    }

    static readonly HashSet<string> StandardKeys =
        [KdbxEntry.TitleKey, KdbxEntry.UserNameKey, KdbxEntry.PasswordKey, KdbxEntry.UrlKey, KdbxEntry.NotesKey];

    static readonly string[] SecretFieldHints = ["password", "secret", "otp", "pin"];

    /// <summary>Custom fields that look secret are stored protected.</summary>
    static bool ShouldProtect(string fieldName) =>
        SecretFieldHints.Any(hint => fieldName.Contains(hint, StringComparison.OrdinalIgnoreCase));

    /// <summary>An entry and the names of the groups containing it (excluding the root group).</summary>
    readonly record struct EntryInGroup(KdbxEntry Entry, IReadOnlyList<string> Path);

    /// <summary>All entries outside the recycle bin, depth first.</summary>
    static IEnumerable<EntryInGroup> AllEntries(KdbxDatabase db)
    {
        var recycleBin = db.RecycleBinUuid;
        var stack = new Stack<(KdbxGroup group, List<string> path)>([(db.RootGroup, [])]);
        while (stack.TryPop(out var current))
        {
            foreach (var entry in current.group.Entries)
                yield return new(entry, current.path);
            foreach (var child in current.group.Groups.Reverse())
            {
                if (recycleBin is null || child.Uuid != recycleBin)
                    stack.Push((child, [.. current.path, child.Name]));
            }
        }
    }

    sealed class Source(KdbxDatabase db) : ICredentialSource
    {
        public IReadOnlyList<Credential> ReadCredentials() => AllEntries(db).Select(ToCredential).ToList();

        static Credential ToCredential(EntryInGroup item)
        {
            var entry = item.Entry;
            var c = new Credential
            {
                Title = entry.GetString(KdbxEntry.TitleKey),
                Username = entry.GetString(KdbxEntry.UserNameKey),
                Password = entry.GetString(KdbxEntry.PasswordKey),
                Url = entry.GetString(KdbxEntry.UrlKey),
                Notes = entry.GetString(KdbxEntry.NotesKey),
                Created = entry.CreationTime,
                Modified = entry.LastModificationTime,
                LastUsed = entry.LastAccessTime,
            };
            foreach (var folder in item.Path)
                c.Folder.Add(folder);
            foreach (var (name, value) in entry.Strings)
            {
                if (!StandardKeys.Contains(name) && value.Length > 0)
                    c.Fields[name] = value;
            }
            return c;
        }

        public void Dispose() { }
    }

    sealed class Target(KdbxDatabase db, string file, KdbxKey key, string[] groupPath, bool skipDuplicates, bool backup)
        : ICredentialTarget
    {
        public WriteResult Write(IReadOnlyList<Credential> credentials)
        {
            // Duplicates are matched on URL + username + password, anywhere in the database.
            var existing = AllEntries(db)
                .Select(e => (e.Entry.GetString(KdbxEntry.UrlKey), e.Entry.GetString(KdbxEntry.UserNameKey), e.Entry.GetString(KdbxEntry.PasswordKey)))
                .ToHashSet();

            KdbxGroup? baseGroup = null;
            KdbxGroup BaseGroup() => baseGroup ??= groupPath.Aggregate(db.RootGroup, (g, name) => g.GetOrAddGroup(name));

            int added = 0, skipped = 0;
            foreach (var c in credentials)
            {
                if (skipDuplicates && !existing.Add((c.Url, c.Username, c.Password)))
                {
                    skipped++;
                    continue;
                }

                var entry = c.Folder.Aggregate(BaseGroup(), (g, name) => g.GetOrAddGroup(name)).AddEntry();
                entry.SetString(KdbxEntry.TitleKey, c.DisplayTitle);
                entry.SetString(KdbxEntry.UserNameKey, c.Username);
                entry.SetString(KdbxEntry.PasswordKey, c.Password, protect: true);
                entry.SetString(KdbxEntry.UrlKey, c.Url);
                entry.SetString(KdbxEntry.NotesKey, c.Notes);
                foreach (var (name, value) in c.Fields)
                {
                    if (!StandardKeys.Contains(name))
                        entry.SetString(name, value, ShouldProtect(name));
                }
                entry.SetTimes(c.Created, c.Modified ?? c.Created, c.LastUsed);
                added++;
            }

            if (added > 0 || !File.Exists(file))
            {
                try
                {
                    db.Save(file, key, backup);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    throw new ProviderException($"Could not save '{file}': {e.Message}", e);
                }
            }
            return new(added, skipped, Path.GetFullPath(file));
        }

        public void Dispose() { }
    }
}
