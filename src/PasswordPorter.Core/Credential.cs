namespace PasswordPorter;

/// <summary>
/// A single saved login, independent of where it came from or where it is going.
/// Providers translate their native records to and from this shape.
/// </summary>
public sealed class Credential
{
    public string? Title { get; set; }
    public string? Url { get; set; }
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? Notes { get; set; }

    /// <summary>Folder path, outermost first (e.g. <c>["Work", "Servers"]</c>). Empty means the top level.</summary>
    public IList<string> Folder { get; } = [];

    /// <summary>Extra named fields without a dedicated property (HTTP realm, TOTP secret, custom fields...).</summary>
    public IDictionary<string, string> Fields { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Creation time in UTC, if known.</summary>
    public DateTime? Created { get; set; }

    /// <summary>Last modification time in UTC, if known.</summary>
    public DateTime? Modified { get; set; }

    /// <summary>Last time the login was used, in UTC, if known.</summary>
    public DateTime? LastUsed { get; set; }

    /// <summary>The title, falling back to the URL's host name.</summary>
    public string DisplayTitle =>
        !string.IsNullOrEmpty(Title) ? Title
        : Uri.TryCreate(Url, UriKind.Absolute, out var uri) && uri.Host.Length > 0 ? uri.Host
        : Url ?? "(untitled)";

    public override string ToString() =>
        string.IsNullOrEmpty(Username) ? DisplayTitle : $"{DisplayTitle} ({Username})";
}
