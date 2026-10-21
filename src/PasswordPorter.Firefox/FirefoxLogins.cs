using System.Text.Json;
using System.Text.Json.Serialization;
using PasswordPorter.Providers;

namespace PasswordPorter.Firefox;

/// <summary>One entry of a profile's logins.json. Username and password are NSS-encrypted, base64-encoded.</summary>
internal sealed record FirefoxLogin(
    string? Hostname,
    string? HttpRealm,
    string? EncryptedUsername,
    string? EncryptedPassword,
    long? TimeCreated,
    long? TimeLastUsed,
    long? TimePasswordChanged);

internal sealed record FirefoxLoginsFile(List<FirefoxLogin>? Logins);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(FirefoxLoginsFile))]
internal sealed partial class FirefoxJsonContext : JsonSerializerContext;

internal static class FirefoxLogins
{
    public static IReadOnlyList<FirefoxLogin> Parse(string json)
    {
        try
        {
            return JsonSerializer.Deserialize(json, FirefoxJsonContext.Default.FirefoxLoginsFile)?.Logins ?? [];
        }
        catch (JsonException e)
        {
            throw new ProviderException("logins.json is not valid: " + e.Message, e);
        }
    }
}
