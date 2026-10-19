using System;

namespace PasswordPorter;

public static class UrlHelper
{
    /// <summary>Returns the host part of an absolute URL, or null if <paramref name="url"/> is not one.</summary>
    public static string? GetHost(string? url)
    {
        if (string.IsNullOrEmpty(url))
            return null;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
            return uri.Host;
        return null;
    }

    /// <summary>Converts milliseconds since the Unix epoch to a UTC <see cref="DateTime"/>; null for missing/zero values.</summary>
    public static DateTime? FromUnixMilliseconds(long? ms)
    {
        if (ms is null || ms.Value <= 0)
            return null;
        return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(ms.Value);
    }
}
