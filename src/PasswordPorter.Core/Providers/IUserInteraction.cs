namespace PasswordPorter.Providers;

/// <summary>
/// How providers talk to the user. Keeps the library free of console (or GUI) code.
/// </summary>
public interface IUserInteraction
{
    /// <summary>
    /// Asks for a secret such as a master password. With <paramref name="confirm"/> the user
    /// is asked to type it twice (used when creating something new).
    /// Returns null when no answer is available (non-interactive, cancelled).
    /// </summary>
    string? PromptSecret(string prompt, bool confirm);

    void Warn(string message);
}

/// <summary>Never prompts; warnings are discarded.</summary>
public sealed class NonInteractive : IUserInteraction
{
    public static readonly NonInteractive Instance = new NonInteractive();

    public string? PromptSecret(string prompt, bool confirm) => null;

    public void Warn(string message) { }
}
