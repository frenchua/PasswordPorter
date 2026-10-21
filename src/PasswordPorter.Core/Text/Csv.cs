using System.Text;

namespace PasswordPorter.Text;

/// <summary>RFC 4180 CSV reading and writing (quoted fields, embedded newlines and quotes).</summary>
public static class Csv
{
    public static IEnumerable<string[]> Read(TextReader reader, char delimiter = ',')
    {
        List<string> row = [];
        var field = new StringBuilder();
        bool inQuotes = false, rowHasContent = false;
        int c;

        while ((c = reader.Read()) != -1)
        {
            var ch = (char)c;
            if (inQuotes)
            {
                if (ch != '"') field.Append(ch);
                else if (reader.Peek() == '"') { reader.Read(); field.Append('"'); }
                else inQuotes = false;
                continue;
            }

            if (ch == '"') { inQuotes = true; rowHasContent = true; }
            else if (ch == delimiter) { row.Add(field.ToString()); field.Clear(); rowHasContent = true; }
            else if (ch is '\r' or '\n')
            {
                if (ch == '\r' && reader.Peek() == '\n') reader.Read();
                if (rowHasContent || field.Length > 0)
                {
                    row.Add(field.ToString());
                    yield return [.. row];
                }
                row.Clear(); field.Clear(); rowHasContent = false;
            }
            else { field.Append(ch); rowHasContent = true; }
        }

        if (rowHasContent || field.Length > 0)
        {
            row.Add(field.ToString());
            yield return [.. row];
        }
    }

    public static void WriteRow(TextWriter writer, IEnumerable<string?> fields, char delimiter = ',')
    {
        char[] needsQuotes = [delimiter, '"', '\r', '\n'];
        writer.Write(string.Join(delimiter, fields.Select(f => f ?? "").Select(value =>
            value.IndexOfAny(needsQuotes) >= 0 || value.StartsWith(' ') || value.EndsWith(' ')
                ? $"\"{value.Replace("\"", "\"\"")}\""
                : value)));
        writer.Write("\r\n");
    }
}
