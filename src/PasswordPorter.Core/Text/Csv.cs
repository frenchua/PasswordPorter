using System.Text;

namespace PasswordPorter.Text;

/// <summary>RFC 4180 CSV reading and writing (quoted fields, embedded newlines and quotes).</summary>
public static class Csv
{
    public static IEnumerable<string[]> Read(TextReader reader, char delimiter = ',')
    {
        var row = new List<string>();
        var field = new StringBuilder();
        bool inQuotes = false, rowHasContent = false;
        int c;

        while ((c = reader.Read()) != -1)
        {
            var ch = (char)c;
            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (reader.Peek() == '"') { reader.Read(); field.Append('"'); }
                    else inQuotes = false;
                }
                else field.Append(ch);
                continue;
            }

            if (ch == '"') { inQuotes = true; rowHasContent = true; }
            else if (ch == delimiter) { row.Add(field.ToString()); field.Clear(); rowHasContent = true; }
            else if (ch == '\r' || ch == '\n')
            {
                if (ch == '\r' && reader.Peek() == '\n') reader.Read();
                if (rowHasContent || field.Length > 0)
                {
                    row.Add(field.ToString());
                    yield return row.ToArray();
                }
                row.Clear(); field.Clear(); rowHasContent = false;
            }
            else { field.Append(ch); rowHasContent = true; }
        }

        if (rowHasContent || field.Length > 0)
        {
            row.Add(field.ToString());
            yield return row.ToArray();
        }
    }

    public static void WriteRow(TextWriter writer, IEnumerable<string?> fields, char delimiter = ',')
    {
        bool first = true;
        foreach (var f in fields)
        {
            if (!first) writer.Write(delimiter);
            first = false;
            var value = f ?? "";
            if (value.IndexOfAny(new[] { delimiter, '"', '\r', '\n' }) >= 0 || value.StartsWith(" ") || value.EndsWith(" "))
                writer.Write("\"" + value.Replace("\"", "\"\"") + "\"");
            else
                writer.Write(value);
        }
        writer.Write("\r\n");
    }
}
