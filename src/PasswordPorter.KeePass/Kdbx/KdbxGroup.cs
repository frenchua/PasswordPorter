using System.Xml.Linq;

namespace PasswordPorter.KeePass.Kdbx;

/// <summary>A view over a &lt;Group&gt; element of the database XML.</summary>
public sealed class KdbxGroup
{
    internal const string ZeroUuid = "AAAAAAAAAAAAAAAAAAAAAA==";

    readonly KdbxDatabase db;

    internal KdbxGroup(KdbxDatabase db, XElement element)
    {
        this.db = db;
        Element = element;
    }

    public XElement Element { get; }

    public string Name => Element.Element("Name")?.Value ?? "";

    public string? Uuid => Element.Element("UUID")?.Value;

    public IEnumerable<KdbxGroup> Groups => Element.Elements("Group").Select(e => new KdbxGroup(db, e));

    public IEnumerable<KdbxEntry> Entries => Element.Elements("Entry").Select(e => new KdbxEntry(db, e));

    /// <summary>Returns the child group with this name, creating it if needed.</summary>
    public KdbxGroup GetOrAddGroup(string name)
    {
        var existing = Groups.FirstOrDefault(g => g.Name == name);
        if (existing != null)
            return existing;
        var element = CreateElement(db, name, iconId: 48);
        Element.Add(element);
        return new KdbxGroup(db, element);
    }

    /// <summary>Adds an empty entry (entries are placed before child groups, as KeePass writes them).</summary>
    public KdbxEntry AddEntry()
    {
        var now = DateTime.UtcNow;
        var element = new XElement("Entry",
            new XElement("UUID", NewUuid()),
            new XElement("IconID", 0),
            new XElement("ForegroundColor"),
            new XElement("BackgroundColor"),
            new XElement("OverrideURL"),
            new XElement("Tags"),
            CreateTimes(db, now),
            new XElement("AutoType",
                new XElement("Enabled", "True"),
                new XElement("DataTransferObfuscation", 0)),
            new XElement("History"));

        var lastEntry = Element.Elements("Entry").LastOrDefault();
        var firstGroup = Element.Elements("Group").FirstOrDefault();
        if (lastEntry != null) lastEntry.AddAfterSelf(element);
        else if (firstGroup != null) firstGroup.AddBeforeSelf(element);
        else Element.Add(element);
        return new KdbxEntry(db, element);
    }

    internal static XElement CreateElement(KdbxDatabase db, string name, int iconId) =>
        new XElement("Group",
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
        return new XElement("Times",
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
public sealed class KdbxEntry
{
    public const string TitleKey = "Title";
    public const string UserNameKey = "UserName";
    public const string PasswordKey = "Password";
    public const string UrlKey = "URL";
    public const string NotesKey = "Notes";

    readonly KdbxDatabase db;

    internal KdbxEntry(KdbxDatabase db, XElement element)
    {
        this.db = db;
        Element = element;
    }

    public XElement Element { get; }

    /// <summary>All string fields (standard and custom), excluding history.</summary>
    public IEnumerable<KeyValuePair<string, string>> Strings =>
        Element.Elements("String").Select(s => new KeyValuePair<string, string>(
            s.Element("Key")?.Value ?? "", s.Element("Value")?.Value ?? ""));

    public string? GetString(string key) =>
        Element.Elements("String").FirstOrDefault(s => s.Element("Key")?.Value == key)?.Element("Value")?.Value;

    public void SetString(string key, string? value, bool protect = false)
    {
        var existing = Element.Elements("String").FirstOrDefault(s => s.Element("Key")?.Value == key);
        var valueElement = new XElement("Value", value ?? "");
        if (protect)
            valueElement.SetAttributeValue("Protected", "True");
        var element = new XElement("String", new XElement("Key", key), valueElement);

        if (existing != null)
        {
            existing.ReplaceWith(element);
            return;
        }
        var anchor = (XElement?)Element.Elements("String").LastOrDefault() ?? Element.Element("Times");
        if (anchor != null) anchor.AddAfterSelf(element);
        else Element.Add(element);
    }

    public DateTime? CreationTime => Time("CreationTime");
    public DateTime? LastModificationTime => Time("LastModificationTime");
    public DateTime? LastAccessTime => Time("LastAccessTime");

    DateTime? Time(string name) => KdbxDatabase.ParseTime(Element.Element("Times")?.Element(name)?.Value);

    public void SetTimes(DateTime? created, DateTime? modified, DateTime? accessed)
    {
        var times = Element.Element("Times");
        if (times == null)
            return;
        void Set(string name, DateTime? value)
        {
            if (value.HasValue)
                times.SetElementValue(name, db.FormatTime(value.Value));
        }
        Set("CreationTime", created);
        Set("LastModificationTime", modified);
        Set("LastAccessTime", accessed);
    }
}
