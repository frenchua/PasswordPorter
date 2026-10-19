using System;
using System.Collections.Generic;

namespace PasswordPorter.Providers;

public enum ProviderKind
{
    Browser,
    PasswordManager,
    File,
}

/// <summary>Static description of a provider.</summary>
public sealed class ProviderInfo
{
    public ProviderInfo(string id, string displayName, ProviderKind kind, string description)
    {
        Id = id;
        DisplayName = displayName;
        Kind = kind;
        Description = description;
    }

    /// <summary>Short, lower-case identifier used on the command line (e.g. <c>firefox</c>).</summary>
    public string Id { get; }
    public string DisplayName { get; }
    public ProviderKind Kind { get; }
    public string Description { get; }
}

/// <summary>
/// Base interface for everything that knows about one browser, password manager or file format.
/// A provider implements <see cref="ICredentialSourceProvider"/>, <see cref="ICredentialTargetProvider"/>,
/// or both, and optionally <see cref="IProfileDiscovery"/>.
/// </summary>
public interface ICredentialProvider
{
    ProviderInfo Info { get; }
}

/// <summary>A provider that credentials can be read from.</summary>
public interface ICredentialSourceProvider : ICredentialProvider
{
    IReadOnlyList<ProviderOption> SourceOptions { get; }

    /// <summary>Opens the store. May prompt (through <see cref="ProviderContext.Interaction"/>) for secrets.</summary>
    ICredentialSource OpenSource(ProviderContext context);
}

/// <summary>A provider that credentials can be written to.</summary>
public interface ICredentialTargetProvider : ICredentialProvider
{
    IReadOnlyList<ProviderOption> TargetOptions { get; }

    ICredentialTarget OpenTarget(ProviderContext context);
}

/// <summary>Implemented by providers that can find their stores on this machine (e.g. browser profiles).</summary>
public interface IProfileDiscovery
{
    IReadOnlyList<ProfileInfo> DiscoverProfiles();
}

public interface ICredentialSource : IDisposable
{
    /// <summary>Reads and decrypts every credential in the store.</summary>
    IReadOnlyList<Credential> ReadCredentials();
}

public interface ICredentialTarget : IDisposable
{
    /// <summary>Writes the credentials to the store and persists it.</summary>
    WriteResult Write(IReadOnlyList<Credential> credentials);
}

public sealed class ProfileInfo
{
    public ProfileInfo(string name, string path, bool isDefault)
    {
        Name = name;
        Path = path;
        IsDefault = isDefault;
    }

    public string Name { get; }
    public string Path { get; }
    public bool IsDefault { get; }
}

public sealed class WriteResult
{
    public WriteResult(int added, int skipped, string? location)
    {
        Added = added;
        Skipped = skipped;
        Location = location;
    }

    public int Added { get; }

    /// <summary>Credentials not written, e.g. because an identical one already existed.</summary>
    public int Skipped { get; }

    /// <summary>Where the credentials ended up (a file path, for instance), for display.</summary>
    public string? Location { get; }
}

/// <summary>
/// An error the user can act on (wrong password, missing file, unsupported format...).
/// Front ends show the message without a stack trace.
/// </summary>
public class ProviderException : Exception
{
    public ProviderException(string message) : base(message) { }
    public ProviderException(string message, Exception inner) : base(message, inner) { }
}
