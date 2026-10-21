namespace PasswordPorter.Providers;

/// <summary>The set of providers a front end offers, looked up by <see cref="ProviderInfo.Id"/>.</summary>
public sealed class ProviderRegistry
{
    readonly List<ICredentialProvider> providers = new List<ICredentialProvider>();

    public IReadOnlyList<ICredentialProvider> Providers => providers;

    public ProviderRegistry Register(ICredentialProvider provider)
    {
        if (Find(provider.Info.Id) != null)
            throw new ArgumentException($"A provider with id '{provider.Info.Id}' is already registered.", nameof(provider));
        providers.Add(provider);
        return this;
    }

    public ICredentialProvider? Find(string id) =>
        providers.FirstOrDefault(p => string.Equals(p.Info.Id, id, StringComparison.OrdinalIgnoreCase));

    public ICredentialProvider Get(string id) =>
        Find(id) ?? throw new ProviderException(
            $"Unknown provider '{id}'. Available: {string.Join(", ", providers.Select(p => p.Info.Id))}.");
}
