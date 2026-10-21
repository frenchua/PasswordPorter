using System.Text;

namespace PasswordPorter.Providers.Csv;

/// <summary>
/// Plain CSV files. Reading recognises the column names used by common exporters (Firefox, Chrome,
/// Bitwarden, KeePass); writing uses <c>title,url,username,password,notes,folder</c> plus one column per extra field.
/// </summary>
public sealed class CsvProvider : ICredentialSourceProvider, ICredentialTargetProvider
{
    const string StdIo = "-";

    public ProviderInfo Info { get; } = new(
        "csv", "CSV file", ProviderKind.File,
        "Unencrypted CSV. Reads exports from Firefox, Chrome, Bitwarden, KeePass and similar; writes a generic layout.");

    public IReadOnlyList<ProviderOption> SourceOptions { get; } =
    [
        new("file", "CSV file to read, or '-' for standard input.", IsRequired: true),
        new("delimiter", "Field delimiter.", DefaultValue: ","),
    ];

    public IReadOnlyList<ProviderOption> TargetOptions { get; } =
    [
        new("file", "CSV file to write, or '-' for standard output.", IsRequired: true),
        new("delimiter", "Field delimiter.", DefaultValue: ","),
        new("overwrite", "Replace the file if it already exists.", DefaultValue: "false"),
    ];

    public ICredentialSource OpenSource(ProviderContext context)
    {
        var file = context.GetRequired("file");
        if (file != StdIo && !File.Exists(file))
            throw new ProviderException($"File not found: {file}");
        return new Source(file, GetDelimiter(context));
    }

    public ICredentialTarget OpenTarget(ProviderContext context)
    {
        var file = context.GetRequired("file");
        if (file != StdIo && File.Exists(file) && !context.GetBool("overwrite"))
            throw new ProviderException($"'{file}' already exists. Pass overwrite=true to replace it.");
        context.Interaction.Warn("CSV files are not encrypted. Delete the file securely once you are done with it.");
        return new Target(file, GetDelimiter(context));
    }

    static char GetDelimiter(ProviderContext context) => (context.Get("delimiter") ?? ",") switch
    {
        @"\t" => '\t',
        var d when d.Equals("tab", StringComparison.OrdinalIgnoreCase) => '\t',
        [var c] => c,
        _ => throw new ProviderException("Option 'delimiter' must be a single character."),
    };

    // Column-name aliases, all compared case-insensitively.
    static readonly string[] TitleColumns = ["title", "name", "account"];
    static readonly string[] UrlColumns = ["url", "login_uri", "uri", "website", "web site", "hostname", "origin"];
    static readonly string[] UsernameColumns = ["username", "login_username", "user name", "user", "login", "email"];
    static readonly string[] PasswordColumns = ["password", "login_password"];
    static readonly string[] NotesColumns = ["notes", "note", "comments", "extra"];
    static readonly string[] FolderColumns = ["folder", "group", "grouping", "path"];

    sealed class Source(string file, char delimiter) : ICredentialSource
    {
        public IReadOnlyList<Credential> ReadCredentials()
        {
            if (file == StdIo)
                return Read(Console.In);
            using var reader = new StreamReader(file, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return Read(reader);
        }

        IReadOnlyList<Credential> Read(TextReader reader)
        {
            using var rows = Text.Csv.Read(reader, delimiter).GetEnumerator();
            if (!rows.MoveNext())
                return [];

            var header = rows.Current.Select(h => h.Trim().TrimStart('﻿')).ToArray();
            int Find(string[] names) => Array.FindIndex(header, h => names.Contains(h, StringComparer.OrdinalIgnoreCase));
            int title = Find(TitleColumns), url = Find(UrlColumns), user = Find(UsernameColumns),
                pass = Find(PasswordColumns), notes = Find(NotesColumns), folder = Find(FolderColumns);
            if (url < 0 && user < 0 && pass < 0)
                throw new ProviderException("The CSV header has no url, username or password column.");
            HashSet<int> known = [title, url, user, pass, notes, folder];

            List<Credential> result = [];
            while (rows.MoveNext())
            {
                var row = rows.Current;
                string? Cell(int i) => i >= 0 && i < row.Length && row[i].Length > 0 ? row[i] : null;

                var c = new Credential
                {
                    Title = Cell(title),
                    Url = Cell(url),
                    Username = Cell(user),
                    Password = Cell(pass),
                    Notes = Cell(notes),
                };
                foreach (var part in Cell(folder)?.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries) ?? [])
                    c.Folder.Add(part);
                for (int i = 0; i < header.Length; i++)
                {
                    if (!known.Contains(i) && header[i].Length > 0 && Cell(i) is { } value)
                        c.Fields[header[i]] = value;
                }
                result.Add(c);
            }
            return result;
        }

        public void Dispose() { }
    }

    sealed class Target(string file, char delimiter) : ICredentialTarget
    {
        public WriteResult Write(IReadOnlyList<Credential> credentials)
        {
            var extra = credentials.SelectMany(c => c.Fields.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
            var writer = file == StdIo ? Console.Out : new StreamWriter(file, false, new UTF8Encoding(false));
            try
            {
                Text.Csv.WriteRow(writer, ["title", "url", "username", "password", "notes", "folder", .. extra], delimiter);
                foreach (var c in credentials)
                {
                    Text.Csv.WriteRow(writer,
                        [c.Title, c.Url, c.Username, c.Password, c.Notes, string.Join("/", c.Folder),
                         .. extra.Select(key => c.Fields.TryGetValue(key, out var v) ? v : null)],
                        delimiter);
                }
            }
            finally
            {
                if (file == StdIo) writer.Flush();
                else writer.Dispose();
            }
            return new(credentials.Count, 0, file == StdIo ? "standard output" : Path.GetFullPath(file));
        }

        public void Dispose() { }
    }
}
