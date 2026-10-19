namespace PasswordPorter.Providers;

/// <summary>A named setting a provider accepts (e.g. <c>file</c>, <c>profile</c>, <c>password</c>).</summary>
public sealed class ProviderOption
{
    public ProviderOption(string name, string description, bool required = false, bool secret = false, string? defaultValue = null)
    {
        Name = name;
        Description = description;
        IsRequired = required;
        IsSecret = secret;
        DefaultValue = defaultValue;
    }

    public string Name { get; }
    public string Description { get; }
    public bool IsRequired { get; }

    /// <summary>
    /// Secret options are prompted for when not supplied, and can also be given
    /// indirectly through an environment variable named by <c>&lt;name&gt;-env</c>.
    /// </summary>
    public bool IsSecret { get; }

    public string? DefaultValue { get; }
}
