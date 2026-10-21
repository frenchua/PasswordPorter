using System.Xml.Linq;

namespace PasswordPorter.KeePass.Kdbx;

/// <summary>A view over a &lt;Group&gt; element of the database XML.</summary>
public sealed class KdbxGroup(KdbxDatabase db, XElement element)
{
    internal const string ZeroUuid = "AAAAAAAAAAAAAAAAAAAAAA==";

    public XElement Element { get; } = element;

    public string Name => Element.Element("Name")?.Value ?? "";

    public string? Uuid => Element.Element("UUID")?.Value;

    public IEnumerable<KdbxGroup> Groups => Element.Elements("Group").Select(e => new KdbxGroup(db, e));

    public IEnumerable<KdbxEntry> Entries => Element.Elements("Entry").Select(e => new KdbxEntry(db, e));

    /// <summary>Returns the child group with this name, creating it if needed.</summary>
    public KdbxGroup GetOrAddGroup(string name)
    {
        if (Groups.FirstOrDefault(g => g.Name == name) is { } existing)
            return existing;
        var child = CreateElement(db, name, iconId: 48);
        Element.Add(child);
        return new(db, child);
    }

    /// <summary>Adds an empty entry (entries are placed before child groups, as KeePass writes them).</summary>
    public KdbxEntry AddEntry()
    {
        var entry = new XElement("Entry",
            new XElement("UUID", NewUuid()),
            new XElement("IconID", 0),
            new XElement("ForegroundColor"),
            new XElement("BackgroundColor"),
            new XElement("OverrideURL"),
            new XElement("Tags"),
            CreateTimes(db, DateTime.UtcNow),
            new XElement("AutoType",
                new XElement("Enabled", "True"),
                new XElement("DataTransferObfuscation", 0)),
            new XElement("History"));

        if (Element.Elements("Entry").LastOrDefault() is { } lastEntry) lastEntry.AddAfterSelf(entry);
        else if (Element.Element("Group") is { } firstGroup) firstGroup.AddBeforeSelf(entry);
        else Element.Add(entry);
        return new(db, entry);
    }

    internal static XElement CreateElement(KdbxDatabase db, string name, int iconId) =>
        new("Group",
            new XElement("UUID", NewUuid()),
            new XElement("Name", name),
            new XElement("Notes"),
            new XElement("IconID", iconId),
            CreateTimes(db, DateTime.UtcNow),
            new XElement("IsExpanded", "True"),
            new XElement("DefaultAutoTypeSequence"),
            new XElement("EnableAutoType", "null"),
            new XElement("EnableSearching", "null"),
            new XElement("LastTopVisibleEntry", ZeroUuid));

    internal static XElement CreateTimes(KdbxDatabase db, DateTime now)
    {
        var t = db.FormatTime(now);
        return new("Times",
            new XElement("CreationTime", t),
            new XElement("LastModificationTime", t),
            new XElement("LastAccessTime", t),
            new XElement("ExpiryTime", t),
            new XElement("Expires", "False"),
            new XElement("UsageCount", 0),
            new XElement("LocationChanged", t));
    }

    static string NewUuid() => Convert.ToBase64String(Guid.NewGuid().ToByteArray());
}

/// <summary>A view over an &lt;Entry&gt; element of the database XML.</summary>
public sealed class KdbxEntry(KdbxDatabase db, XElement element)
{
    public const string TitleKey = "Title";
    public const string UserNameKey = "UserName";
    public const string PasswordKey = "Password";
    public const string UrlKey = "URL";
    public const string NotesKey = "Notes";

    public XElement Element { get; } = element;

    /// <summary>All string fields (standard and custom), excluding history.</summary>
    public IEnumerable<KeyValuePair<string, string>> Strings =>
        Element.Elements("String").Select(s => KeyValuePair.Create(s.Element("Key")?.Value ?? "", s.Element("Value")?.Value ?? ""));

    XElement? FindString(string key) => Element.Elements("String").FirstOrDefault(s => s.Element("Key")?.Value == key);

    public string? GetString(string key) => FindString(key)?.Element("Value")?.Value;

    public void SetString(string key, string? value, bool protect = false)
    {
        var valueElement = new XElement("Value", value ?? "");
        if (protect)
            valueElement.SetAttributeValue("Protected", "True");
        var str = new XElement("String", new XElement("Key", key), valueElement);

        if (FindString(key) is { } existing)
            existing.ReplaceWith(str);
        else if ((Element.Elements("String").LastOrDefault() ?? Element.Element("Times")) is { } anchor)
            anchor.AddAfterSelf(str);
        else
            Element.Add(str);
    }

    public DateTime? CreationTime => Time("CreationTime");
    public DateTime? LastModificationTime => Time("LastModificationTime");
    public DateTime? LastAccessTime => Time("LastAccessTime");

    DateTime? Time(string name) => KdbxDatabase.ParseTime(Element.Element("Times")?.Element(name)?.Value);

    public void SetTimes(DateTime? created, DateTime? modified, DateTime? accessed)
    {
        if (Element.Element("Times") is not { } times)
            return;
        foreach (var (name, value) in (ReadOnlySpan<(string, DateTime?)>)
                 [("CreationTime", created), ("LastModificationTime", modified), ("LastAccessTime", accessed)])
        {
            if (value is { } t)
                times.SetElementValue(name, db.FormatTime(t));
        }
    }
}
