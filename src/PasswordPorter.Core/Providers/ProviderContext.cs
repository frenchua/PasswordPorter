using System.Globalization;

namespace PasswordPorter.Providers;

/// <summary>
/// Settings and user interaction handed to a provider when it opens a source or target.
/// </summary>
public sealed class ProviderContext
{
    const string EnvSuffix = "-env";

    readonly Dictionary<string, string> settings = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, ProviderOption> options;

    /// <summary>
    /// Creates a context, checking <paramref name="settings"/> against the provider's declared
    /// <paramref name="options"/>. Unknown settings are rejected so typos don't go unnoticed.
    /// </summary>
    public ProviderContext(IReadOnlyList<ProviderOption> options, IDictionary<string, string>? settings, IUserInteraction? interaction = null)
    {
        this.options = options.ToDictionary(o => o.Name, StringComparer.OrdinalIgnoreCase);
        Interaction = interaction ?? NonInteractive.Instance;

        foreach (var (key, value) in settings?.AsEnumerable() ?? [])
        {
            if (!IsKnown(key))
            {
                var known = string.Join(", ", options.Select(o => o.Name));
                throw new ProviderException($"Unknown option '{key}'. Valid options: {(known is "" ? "(none)" : known)}.");
            }
            this.settings[key] = value;
        }

        if (options.FirstOrDefault(o => o is { IsRequired: true, IsSecret: false } && Get(o.Name) is null) is { } missing)
            throw new ProviderException($"Missing required option '{missing.Name}': {missing.Description}");
    }

    public IUserInteraction Interaction { get; }

    bool IsKnown(string name) =>
        options.ContainsKey(name)
        || (name.EndsWith(EnvSuffix, StringComparison.OrdinalIgnoreCase)
            && options.TryGetValue(name[..^EnvSuffix.Length], out var o)
            && o.IsSecret);

    /// <summary>The setting's value, the option's default, or null.</summary>
    public string? Get(string name) =>
        settings.TryGetValue(name, out var value) ? value
        : options.TryGetValue(name, out var option) ? option.DefaultValue
        : null;

    public string GetRequired(string name) =>
        Get(name) ?? throw new ProviderException($"Missing required option '{name}'.");

    public bool GetBool(string name, bool defaultValue = false)
    {
        var value = Get(name);
        if (string.IsNullOrEmpty(value))
            return defaultValue;
        return value.Trim().ToLowerInvariant() switch
        {
            "1" or "true" or "yes" or "on" => true,
            "0" or "false" or "no" or "off" => false,
            _ => throw new ProviderException($"Option '{name}' expects true/false, got '{value}'."),
        };
    }

    public long GetInt64(string name, long defaultValue)
    {
        var value = Get(name);
        if (string.IsNullOrEmpty(value))
            return defaultValue;
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result)
            ? result
            : throw new ProviderException($"Option '{name}' expects a whole number, got '{value}'.");
    }

    /// <summary>
    /// Resolves a secret: the setting itself, then the environment variable named by
    /// <c>&lt;name&gt;-env</c>, then a prompt. Returns null if none of these yields a value.
    /// </summary>
    public string? GetSecret(string name, string prompt, bool confirm = false)
    {
        if (settings.TryGetValue(name, out var direct))
            return direct;

        if (settings.TryGetValue(name + EnvSuffix, out var variable))
            return Environment.GetEnvironmentVariable(variable)
                ?? throw new ProviderException($"Environment variable '{variable}' (from option '{name}{EnvSuffix}') is not set.");

        return Interaction.PromptSecret(prompt, confirm);
    }
}
