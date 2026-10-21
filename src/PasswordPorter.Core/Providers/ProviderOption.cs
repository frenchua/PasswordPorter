namespace PasswordPorter.Providers;

/// <summary>A named setting a provider accepts (e.g. <c>file</c>, <c>profile</c>, <c>password</c>).</summary>
/// <param name="IsSecret">
/// Secret options are prompted for when not supplied, and can also be given
/// indirectly through an environment variable named by <c>&lt;name&gt;-env</c>.
/// </param>
public sealed record ProviderOption(
    string Name,
    string Description,
    bool IsRequired = false,
    bool IsSecret = false,
    string? DefaultValue = null);
