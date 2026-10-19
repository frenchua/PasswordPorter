using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace PasswordPorter.Providers;

/// <summary>
/// Settings and user interaction handed to a provider when it opens a source or target.
/// </summary>
public sealed class ProviderContext
{
    readonly Dictionary<string, string> settings;
    readonly Dictionary<string, ProviderOption> options;

    /// <summary>
    /// Creates a context, checking <paramref name="settings"/> against the provider's declared
    /// <paramref name="options"/>. Unknown settings are rejected so typos don't go unnoticed.
    /// </summary>
    public ProviderContext(IReadOnlyList<ProviderOption> options, IDictionary<string, string>? settings, IUserInteraction? interaction = null)
    {
        this.options = options.ToDictionary(o => o.Name, StringComparer.OrdinalIgnoreCase);
        this.settings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Interaction = interaction ?? NonInteractive.Instance;

        if (settings != null)
        {
            foreach (var pair in settings)
            {
                if (!IsKnown(pair.Key))
                {
                    var known = string.Join(", ", options.Select(o => o.Name));
                    throw new ProviderException($"Unknown option '{pair.Key}'. Valid options: {(known.Length == 0 ? "(none)" : known)}.");
                }
                this.settings[pair.Key] = pair.Value;
            }
        }

        foreach (var option in options)
        {
            if (option.IsRequired && !option.IsSecret && Get(option.Name) == null)
                throw new ProviderException($"Missing required option '{option.Name}': {option.Description}");
        }
    }

    public IUserInteraction Interaction { get; }

    bool IsKnown(string name)
    {
        if (options.ContainsKey(name))
            return true;
        const string envSuffix = "-env";
        return name.EndsWith(envSuffix, StringComparison.OrdinalIgnoreCase)
            && options.TryGetValue(name.Substring(0, name.Length - envSuffix.Length), out var o)
            && o.IsSecret;
    }

    /// <summary>The setting's value, the option's default, or null.</summary>
    public string? Get(string name)
    {
        if (settings.TryGetValue(name, out var value))
            return value;
        return options.TryGetValue(name, out var option) ? option.DefaultValue : null;
    }

    public string GetRequired(string name) =>
        Get(name) ?? throw new ProviderException($"Missing required option '{name}'.");

    public bool GetBool(string name, bool defaultValue = false)
    {
        var value = Get(name);
        if (string.IsNullOrEmpty(value))
            return defaultValue;
        switch (value!.Trim().ToLowerInvariant())
        {
            case "1": case "true": case "yes": case "on": return true;
            case "0": case "false": case "no": case "off": return false;
            default: throw new ProviderException($"Option '{name}' expects true/false, got '{value}'.");
        }
    }

    public long GetInt64(string name, long defaultValue)
    {
        var value = Get(name);
        if (string.IsNullOrEmpty(value))
            return defaultValue;
        if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
            throw new ProviderException($"Option '{name}' expects a whole number, got '{value}'.");
        return result;
    }

    /// <summary>
    /// Resolves a secret: the setting itself, then the environment variable named by
    /// <c>&lt;name&gt;-env</c>, then a prompt. Returns null if none of these yields a value.
    /// </summary>
    public string? GetSecret(string name, string prompt, bool confirm = false)
    {
        if (settings.TryGetValue(name, out var direct))
            return direct;

        if (settings.TryGetValue(name + "-env", out var variable))
        {
            var fromEnv = Environment.GetEnvironmentVariable(variable);
            if (fromEnv == null)
                throw new ProviderException($"Environment variable '{variable}' (from option '{name}-env') is not set.");
            return fromEnv;
        }

        return Interaction.PromptSecret(prompt, confirm);
    }
}
