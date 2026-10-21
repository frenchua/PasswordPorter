using System.Text;
using PasswordPorter.Providers;

namespace PasswordPorter.Cli;

/// <summary>Prompts on the console (stderr, so stdout stays clean for piped output).</summary>
internal sealed class ConsoleInteraction : IUserInteraction
{
    public string? PromptSecret(string prompt, bool confirm)
    {
        if (Console.IsInputRedirected)
        {
            // Piped input: take one line per prompt, no confirmation.
            Console.Error.Write(prompt);
            var line = Console.In.ReadLine();
            Console.Error.WriteLine();
            return line;
        }

        while (true)
        {
            var first = ReadMasked(prompt);
            if (first is null || !confirm)
                return first;
            var second = ReadMasked("Repeat to confirm: ");
            if (second is null || first == second)
                return second;
            Console.Error.WriteLine("The passwords do not match. Try again.");
        }
    }

    public void Warn(string message) => Console.Error.WriteLine($"warning: {message}");

    /// <summary>Reads a line without echoing it. Escape cancels (returns null).</summary>
    static string? ReadMasked(string prompt)
    {
        Console.Error.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            switch (key.Key)
            {
                case ConsoleKey.Enter:
                    Console.Error.WriteLine();
                    return sb.ToString();
                case ConsoleKey.Escape:
                    Console.Error.WriteLine();
                    return null;
                case ConsoleKey.Backspace when sb.Length > 0:
                    sb.Length--;
                    Console.Error.Write("\b \b");
                    break;
                case not ConsoleKey.Backspace when !char.IsControl(key.KeyChar):
                    sb.Append(key.KeyChar);
                    Console.Error.Write('*');
                    break;
            }
        }
    }
}
