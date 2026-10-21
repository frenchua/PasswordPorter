using PasswordPorter.KeePass.Kdbx;
using PasswordPorter.Providers;

namespace PasswordPorter.KeePass;

/// <summary>
/// KeePass 2.x / KeePassXC databases. As a target it creates the file if needed, or merges into an
/// existing one without disturbing anything already there.
/// </summary>
public sealed class KeePassProvider : ICredentialSourceProvider, ICredentialTargetProvider
{
    public ProviderInfo Info { get; } = new ProviderInfo(
        "keepass", "KeePass (KDBX)", ProviderKind.PasswordManager,
        "KeePass 2.x / KeePassXC database. Reads KDBX 3.1 and 4.x; adds to existing databases or creates KDBX 4 ones.");

    public IReadOnlyList<ProviderOption> SourceOptions { get; } =
    [
        new ProviderOption("file", "The .kdbx file.", IsRequired: true),
        new ProviderOption("password", "Master password.", IsSecret: true),
        new ProviderOption("keyfile", "Key file, if the database uses one."),
    ];

    public IReadOnlyList<ProviderOption> TargetOptions { get; } =
    [
        new ProviderOption("file", "The .kdbx file. Created if it does not exist, otherwise added to.", IsRequired: true),
        new ProviderOption("password", "Master password.", IsSecret: true),
        new ProviderOption("keyfile", "Key file, if the database uses (or should use) one."),
        new ProviderOption("group", "Group to put imported entries in ('/' separates levels; empty = top level).", DefaultValue: "Imported"),
        new ProviderOption("duplicates", "skip: don't add entries whose URL, username and password already exist anywhere in the database; add: add them anyway.", DefaultValue: "skip"),
        new ProviderOption("backup", "Keep the previous version of an existing database as <file>.bak.", DefaultValue: "true"),
        new ProviderOption("kdf", "New databases only: argon2id, argon2d or aes.", DefaultValue: "argon2id"),
        new ProviderOption("kdf-iterations", "New databases only: Argon2 passes (or AES-KDF rounds)."),
        new ProviderOption("kdf-memory", "New databases only: Argon2 memory in MiB.", DefaultValue: "64"),
        new ProviderOption("kdf-parallelism", "New databases only: Argon2 parallelism.", DefaultValue: "2"),
    ];

    public ICredentialSource OpenSource(ProviderContext context)
    {
        var file = context.GetRequired("file");
        if (!File.Exists(file))
            throw new ProviderException($"File not found: {file}");
        var key = GetKey(context, file, isNew: false);
        return new Source(Open(file, key));
    }

    public ICredentialTarget OpenTarget(ProviderContext context)
    {
        var file = context.GetRequired("file");
        var duplicates = (context.Get("duplicates") ?? "skip").ToLowerInvariant();
        if (duplicates != "skip" && duplicates != "add")
            throw new ProviderException("Option 'duplicates' must be 'skip' or 'add'.");

        var isNew = !File.Exists(file);
        var kdf = isNew ? GetKdfSettings(context) : null;
        var key = GetKey(context, file, isNew);
        var db = isNew ? KdbxDatabase.Create(Path.GetFileNameWithoutExtension(file), kdf) : Open(file, key);

        var group = (context.Get("group") ?? "").Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
        return new Target(db, file, key, group, duplicates == "skip", context.GetBool("backup", true));
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
        if (!string.IsNullOrEmpty(keyFile) && !File.Exists(keyFile))
            throw new ProviderException($"Key file not found: {keyFile}");

        var prompt = isNew
            ? $"New master password for {Path.GetFileName(file)}: "
            : $"Master password for {Path.GetFileName(file)}: ";
        var password = context.GetSecret("password", prompt, confirm: isNew);

        // With a key file, an empty password means "key file only", as in KeePass.
        if (string.IsNullOrEmpty(password) && !string.IsNullOrEmpty(keyFile))
            password = null;
        if (password == null && string.IsNullOrEmpty(keyFile))
            throw new ProviderException("A master password (password=..., password-env=VAR or the prompt) or keyfile=... is required.");
        if (isNew && password != null && password.Length == 0)
            throw new ProviderException("Refusing to create a database with an empty master password.");
        return new KdbxKey(password, keyFile);
    }

    static KdbxKdfSettings GetKdfSettings(ProviderContext context)
    {
        var settings = new KdbxKdfSettings();
        switch ((context.Get("kdf") ?? "argon2id").ToLowerInvariant())
        {
            case "argon2id": settings.Algorithm = KdbxKdfAlgorithm.Argon2id; break;
            case "argon2d": settings.Algorithm = KdbxKdfAlgorithm.Argon2d; break;
            case "aes": case "aes-kdf": settings.Algorithm = KdbxKdfAlgorithm.AesKdf; break;
            default: throw new ProviderException("Option 'kdf' must be argon2id, argon2d or aes.");
        }

        var defaultIterations = settings.Algorithm == KdbxKdfAlgorithm.AesKdf ? 2_000_000L : (long)settings.Iterations;
        var iterations = context.GetInt64("kdf-iterations", defaultIterations);
        var memory = context.GetInt64("kdf-memory", 64);
        var parallelism = context.GetInt64("kdf-parallelism", 2);
        if (iterations < 1 || memory < 1 || memory > 4096 || parallelism < 1 || parallelism > 64)
            throw new ProviderException("KDF settings out of range (iterations >= 1, memory 1-4096 MiB, parallelism 1-64).");

        settings.Iterations = (ulong)iterations;
        settings.MemoryBytes = (ulong)memory * 1024 * 1024;
        settings.Parallelism = (uint)parallelism;
        return settings;
    }

    static readonly HashSet<string> StandardKeys = new HashSet<string>(StringComparer.Ordinal)
    {
        KdbxEntry.TitleKey, KdbxEntry.UserNameKey, KdbxEntry.PasswordKey, KdbxEntry.UrlKey, KdbxEntry.NotesKey,
    };

    /// <summary>Custom fields that look secret are stored protected.</summary>
    static bool ShouldProtect(string fieldName)
    {
        var n = fieldName.ToLowerInvariant();
        return n.Contains("password") || n.Contains("secret") || n.Contains("otp") || n.Contains("pin");
    }

    static string DuplicateKey(string? url, string? user, string? password) =>
        (url ?? "") + "\u0000" + (user ?? "") + "\u0000" + (password ?? "");

    /// <summary>All entries outside the recycle bin, with their group path (excluding the root group).</summary>
    static IEnumerable<KeyValuePair<KdbxEntry, List<string>>> AllEntries(KdbxDatabase db)
    {
        var recycleBin = db.RecycleBinUuid;
        var stack = new Stack<KeyValuePair<KdbxGroup, List<string>>>();
        stack.Push(new KeyValuePair<KdbxGroup, List<string>>(db.RootGroup, new List<string>()));
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            foreach (var entry in current.Key.Entries)
                yield return new KeyValuePair<KdbxEntry, List<string>>(entry, current.Value);
            foreach (var child in current.Key.Groups.Reverse())
            {
                if (recycleBin != null && child.Uuid == recycleBin)
                    continue;
                stack.Push(new KeyValuePair<KdbxGroup, List<string>>(child, new List<string>(current.Value) { child.Name }));
            }
        }
    }

    sealed class Source : ICredentialSource
    {
        readonly KdbxDatabase db;

        public Source(KdbxDatabase db) { this.db = db; }

        public IReadOnlyList<Credential> ReadCredentials()
        {
            var result = new List<Credential>();
            foreach (var pair in AllEntries(db))
            {
                var entry = pair.Key;
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
                foreach (var folder in pair.Value)
                    c.Folder.Add(folder);
                foreach (var s in entry.Strings)
                    if (!StandardKeys.Contains(s.Key) && s.Value.Length > 0)
                        c.Fields[s.Key] = s.Value;
                result.Add(c);
            }
            return result;
        }

        public void Dispose() { }
    }

    sealed class Target : ICredentialTarget
    {
        readonly KdbxDatabase db;
        readonly string file;
        readonly KdbxKey key;
        readonly string[] groupPath;
        readonly bool skipDuplicates;
        readonly bool backup;

        public Target(KdbxDatabase db, string file, KdbxKey key, string[] groupPath, bool skipDuplicates, bool backup)
        {
            this.db = db;
            this.file = file;
            this.key = key;
            this.groupPath = groupPath;
            this.skipDuplicates = skipDuplicates;
            this.backup = backup;
        }

        public WriteResult Write(IReadOnlyList<Credential> credentials)
        {
            var existing = new HashSet<string>(AllEntries(db).Select(p => DuplicateKey(
                p.Key.GetString(KdbxEntry.UrlKey), p.Key.GetString(KdbxEntry.UserNameKey), p.Key.GetString(KdbxEntry.PasswordKey))),
                StringComparer.Ordinal);

            KdbxGroup? baseGroup = null;
            int added = 0, skipped = 0;
            foreach (var c in credentials)
            {
                if (skipDuplicates && !existing.Add(DuplicateKey(c.Url, c.Username, c.Password)))
                {
                    skipped++;
                    continue;
                }

                if (baseGroup == null)
                {
                    baseGroup = db.RootGroup;
                    foreach (var name in groupPath)
                        baseGroup = baseGroup.GetOrAddGroup(name);
                }
                var group = baseGroup;
                foreach (var name in c.Folder)
                    group = group.GetOrAddGroup(name);

                var entry = group.AddEntry();
                entry.SetString(KdbxEntry.TitleKey, c.DisplayTitle);
                entry.SetString(KdbxEntry.UserNameKey, c.Username);
                entry.SetString(KdbxEntry.PasswordKey, c.Password, protect: true);
                entry.SetString(KdbxEntry.UrlKey, c.Url);
                entry.SetString(KdbxEntry.NotesKey, c.Notes);
                foreach (var field in c.Fields)
                    if (!StandardKeys.Contains(field.Key))
                        entry.SetString(field.Key, field.Value, ShouldProtect(field.Key));
                entry.SetTimes(c.Created, c.Modified ?? c.Created, c.LastUsed);
                added++;
            }

            if (added > 0 || !File.Exists(file))
            {
                try
                {
                    db.Save(file, key, backup);
                }
                catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
                {
                    throw new ProviderException($"Could not save '{file}': {e.Message}", e);
                }
            }
            return new WriteResult(added, skipped, Path.GetFullPath(file));
        }

        public void Dispose() { }
    }
}
