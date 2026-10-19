using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PasswordPorter.Text;

namespace PasswordPorter.Providers.Csv;

/// <summary>
/// Plain CSV files. Reading recognises the column names used by common exporters (Firefox, Chrome,
/// Bitwarden, KeePass); writing uses <c>title,url,username,password,notes,folder</c> plus one column per extra field.
/// </summary>
public sealed class CsvProvider : ICredentialSourceProvider, ICredentialTargetProvider
{
    public ProviderInfo Info { get; } = new ProviderInfo(
        "csv", "CSV file", ProviderKind.File,
        "Unencrypted CSV. Reads exports from Firefox, Chrome, Bitwarden, KeePass and similar; writes a generic layout.");

    public IReadOnlyList<ProviderOption> SourceOptions { get; } = new[]
    {
        new ProviderOption("file", "CSV file to read, or '-' for standard input.", required: true),
        new ProviderOption("delimiter", "Field delimiter.", defaultValue: ","),
    };

    public IReadOnlyList<ProviderOption> TargetOptions { get; } = new[]
    {
        new ProviderOption("file", "CSV file to write, or '-' for standard output.", required: true),
        new ProviderOption("delimiter", "Field delimiter.", defaultValue: ","),
        new ProviderOption("overwrite", "Replace the file if it already exists.", defaultValue: "false"),
    };

    public ICredentialSource OpenSource(ProviderContext context) =>
        new Source(context.GetRequired("file"), GetDelimiter(context));

    public ICredentialTarget OpenTarget(ProviderContext context)
    {
        var file = context.GetRequired("file");
        if (file != "-" && File.Exists(file) && !context.GetBool("overwrite"))
            throw new ProviderException($"'{file}' already exists. Pass overwrite=true to replace it.");
        context.Interaction.Warn("CSV files are not encrypted. Delete the file securely once you are done with it.");
        return new Target(file, GetDelimiter(context));
    }

    static char GetDelimiter(ProviderContext context)
    {
        var d = context.Get("delimiter") ?? ",";
        if (d == "\\t" || d.Equals("tab", StringComparison.OrdinalIgnoreCase)) return '\t';
        if (d.Length != 1) throw new ProviderException("Option 'delimiter' must be a single character.");
        return d[0];
    }

    // Column-name aliases, all compared case-insensitively.
    static readonly string[] TitleColumns = { "title", "name", "account" };
    static readonly string[] UrlColumns = { "url", "login_uri", "uri", "website", "web site", "hostname", "origin" };
    static readonly string[] UsernameColumns = { "username", "login_username", "user name", "user", "login", "email" };
    static readonly string[] PasswordColumns = { "password", "login_password" };
    static readonly string[] NotesColumns = { "notes", "note", "comments", "extra" };
    static readonly string[] FolderColumns = { "folder", "group", "grouping", "path" };

    internal sealed class Source : ICredentialSource
    {
        readonly string file;
        readonly char delimiter;

        public Source(string file, char delimiter)
        {
            if (file != "-" && !File.Exists(file))
                throw new ProviderException($"File not found: {file}");
            this.file = file;
            this.delimiter = delimiter;
        }

        public IReadOnlyList<Credential> ReadCredentials()
        {
            if (file == "-")
                return Read(Console.In);
            using var reader = new StreamReader(file, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return Read(reader);
        }

        IReadOnlyList<Credential> Read(TextReader reader)
        {
            using var rows = Text.Csv.Read(reader, delimiter).GetEnumerator();
            if (!rows.MoveNext())
                return Array.Empty<Credential>();

            var header = rows.Current.Select(h => h.Trim().TrimStart('﻿')).ToArray();
            int Find(string[] names) => Array.FindIndex(header, h => names.Any(n => n.Equals(h, StringComparison.OrdinalIgnoreCase)));
            int title = Find(TitleColumns), url = Find(UrlColumns), user = Find(UsernameColumns),
                pass = Find(PasswordColumns), notes = Find(NotesColumns), folder = Find(FolderColumns);
            if (url < 0 && user < 0 && pass < 0)
                throw new ProviderException("The CSV header has no url, username or password column.");
            var known = new HashSet<int> { title, url, user, pass, notes, folder };

            var result = new List<Credential>();
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
                var f = Cell(folder);
                if (f != null)
                    foreach (var part in f.Split('/', '\\'))
                        if (part.Length > 0) c.Folder.Add(part);
                for (int i = 0; i < header.Length; i++)
                {
                    var value = Cell(i);
                    if (!known.Contains(i) && value != null && header[i].Length > 0)
                        c.Fields[header[i]] = value;
                }
                result.Add(c);
            }
            return result;
        }

        public void Dispose() { }
    }

    internal sealed class Target : ICredentialTarget
    {
        readonly string file;
        readonly char delimiter;

        public Target(string file, char delimiter)
        {
            this.file = file;
            this.delimiter = delimiter;
        }

        public WriteResult Write(IReadOnlyList<Credential> credentials)
        {
            var extra = credentials.SelectMany(c => c.Fields.Keys).Distinct(StringComparer.Ordinal).OrderBy(k => k, StringComparer.Ordinal).ToList();
            var writer = file == "-" ? Console.Out : new StreamWriter(file, false, new UTF8Encoding(false));
            try
            {
                Text.Csv.WriteRow(writer, new[] { "title", "url", "username", "password", "notes", "folder" }.Concat(extra), delimiter);
                foreach (var c in credentials)
                {
                    var row = new List<string?> { c.Title, c.Url, c.Username, c.Password, c.Notes, string.Join("/", c.Folder) };
                    foreach (var key in extra)
                        row.Add(c.Fields.TryGetValue(key, out var v) ? v : null);
                    Text.Csv.WriteRow(writer, row, delimiter);
                }
            }
            finally
            {
                if (file == "-") writer.Flush();
                else writer.Dispose();
            }
            return new WriteResult(credentials.Count, 0, file == "-" ? "standard output" : Path.GetFullPath(file));
        }

        public void Dispose() { }
    }
}
