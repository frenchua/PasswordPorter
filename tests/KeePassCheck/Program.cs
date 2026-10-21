using System;
using System.Linq;
using System.Text;
#if HAVE_KEEPASSLIB
using KeePassLib;
using KeePassLib.Cryptography.KeyDerivation;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
#endif

namespace KeePassCheck;

/// <summary>
/// <c>KeePassCheck create &lt;file&gt; &lt;password&gt; &lt;aes|argon2d|argon2id&gt; &lt;aes|chacha20&gt;</c><br/>
///   Creates a database with KeePassLib holding one entry "Theirs" (user "bob", password "new"),
///   with one history version (password "old") and an attachment note.txt = "attachment body".<br/>
/// <c>KeePassCheck dump &lt;file&gt; &lt;password&gt; [keyfile]</c><br/>
///   Opens a database with KeePassLib and prints its entries as JSON.<br/>
/// Exit codes: 0 ok, 1 KeePassLib error (details on stderr), 2 usage, 3 built without KeePass.exe.
/// </summary>
internal static class Program
{
    static int Main(string[] args)
    {
#if HAVE_KEEPASSLIB
        try
        {
            if (args.Length == 5 && args[0] == "create")
            {
                Create(args[1], args[2], args[3], args[4]);
                return 0;
            }
            if ((args.Length == 3 || args.Length == 4) && args[0] == "dump")
            {
                WriteUtf8(Dump(args[1], args[2], args.Length == 4 ? args[3] : null));
                return 0;
            }
            Console.Error.WriteLine("usage: KeePassCheck create <file> <password> <kdf> <cipher> | dump <file> <password> [keyfile]");
            return 2;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e);
            return 1;
        }
#else
        Console.Error.WriteLine("KeePassCheck was built without KeePass.exe.");
        return 3;
#endif
    }

#if HAVE_KEEPASSLIB
    static CompositeKey Key(string password, string keyFile)
    {
        var key = new CompositeKey();
        key.AddUserKey(new KcpPassword(password));
        if (keyFile is not null)
            key.AddUserKey(new KcpKeyFile(keyFile));
        return key;
    }

    static void Create(string path, string password, string kdf, string cipher)
    {
        var db = new PwDatabase();
        db.New(IOConnectionInfo.FromPath(path), Key(password, null));

        // Small KDF settings keep the tests fast.
        if (kdf == "aes")
        {
            var p = new AesKdf().GetDefaultParameters();
            p.SetUInt64(AesKdf.ParamRounds, 1000);
            db.KdfParameters = p;
        }
        else
        {
            var p = new Argon2Kdf(kdf == "argon2d" ? Argon2Type.D : Argon2Type.ID).GetDefaultParameters();
            p.SetUInt64(Argon2Kdf.ParamMemory, 1024 * 1024);
            p.SetUInt64(Argon2Kdf.ParamIterations, 2);
            db.KdfParameters = p;
        }
        if (cipher == "chacha20")
            db.DataCipherUuid = new PwUuid(new byte[] { 0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a });

        var entry = new PwEntry(true, true);
        entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "Theirs"));
        entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, "bob"));
        entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "old"));
        entry.Binaries.Set("note.txt", new ProtectedBinary(false, Encoding.UTF8.GetBytes("attachment body")));
        db.RootGroup.AddEntry(entry, true);
        entry.CreateBackup(db);
        entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "new"));

        db.Save(new NullStatusLogger());
        db.Close();
    }

    /// <summary>
    /// {"entries":[{"group":"A/B","strings":{"Title":"..."},"protected":["Password"],
    ///   "history":[{"Password":"old"}],"binaries":{"note.txt":"base64"}}]}
    /// The group path excludes the root group.
    /// </summary>
    static string Dump(string path, string password, string keyFile)
    {
        var db = new PwDatabase();
        db.Open(IOConnectionInfo.FromPath(path), Key(password, keyFile), new NullStatusLogger());
        try
        {
            var json = new StringBuilder("{\"entries\":[");
            bool first = true;
            foreach (var entry in db.RootGroup.GetEntries(true))
            {
                if (!first) json.Append(',');
                first = false;

                var groups = new System.Collections.Generic.List<string>();
                for (var g = entry.ParentGroup; g is not null && g != db.RootGroup; g = g.ParentGroup)
                    groups.Insert(0, g.Name);

                json.Append("{\"group\":").Append(Str(string.Join("/", groups)));
                json.Append(",\"strings\":").Append(Strings(entry));
                json.Append(",\"protected\":[")
                    .Append(string.Join(",", entry.Strings.Where(s => s.Value.IsProtected).Select(s => Str(s.Key))))
                    .Append(']');
                json.Append(",\"history\":[").Append(string.Join(",", entry.History.Select(Strings))).Append(']');
                json.Append(",\"binaries\":{")
                    .Append(string.Join(",", entry.Binaries.Select(b => Str(b.Key) + ":" + Str(Convert.ToBase64String(b.Value.ReadData())))))
                    .Append("}}");
            }
            return json.Append("]}").ToString();
        }
        finally
        {
            db.Close();
        }
    }

    static string Strings(PwEntry entry) =>
        "{" + string.Join(",", entry.Strings.Select(s => Str(s.Key) + ":" + Str(s.Value.ReadString()))) + "}";

    static string Str(string value)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in value)
        {
            if (c == '"' || c == '\\') sb.Append('\\').Append(c);
            else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
            else sb.Append(c);
        }
        return sb.Append('"').ToString();
    }

    /// <summary>Writes UTF-8 to stdout regardless of the console code page.</summary>
    static void WriteUtf8(string text)
    {
        var bytes = new UTF8Encoding(false).GetBytes(text);
        using var stdout = Console.OpenStandardOutput();
        stdout.Write(bytes, 0, bytes.Length);
    }
#endif
}
