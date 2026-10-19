using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace PasswordPorter.Text;

/// <summary>
/// A small, dependency-free JSON parser (System.Text.Json is not part of .NET Framework).
/// Objects become <see cref="Dictionary{TKey,TValue}"/> of string to object?, arrays become
/// <see cref="List{T}"/> of object?, numbers become <see cref="long"/> when integral and
/// <see cref="double"/> otherwise.
/// </summary>
public static class SimpleJson
{
    public static object? Parse(string json)
    {
        var parser = new Parser(json);
        parser.SkipWhitespace();
        var value = parser.ParseValue();
        parser.SkipWhitespace();
        if (!parser.AtEnd)
            throw parser.Error("Unexpected trailing characters");
        return value;
    }

    public static Dictionary<string, object?>? AsObject(object? value) => value as Dictionary<string, object?>;

    public static List<object?>? AsArray(object? value) => value as List<object?>;

    public static string? GetString(this Dictionary<string, object?> obj, string key) =>
        obj.TryGetValue(key, out var v) ? v as string : null;

    public static long? GetInt64(this Dictionary<string, object?> obj, string key)
    {
        if (!obj.TryGetValue(key, out var v))
            return null;
        if (v is long l) return l;
        if (v is double d) return (long)d;
        return null;
    }

    sealed class Parser
    {
        readonly string s;
        int pos;

        public Parser(string s) { this.s = s; }

        public bool AtEnd => pos >= s.Length;

        public FormatException Error(string message) => new FormatException($"{message} at position {pos} of JSON input.");

        public void SkipWhitespace()
        {
            while (pos < s.Length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\r' || s[pos] == '\n'))
                pos++;
        }

        char Peek() => pos < s.Length ? s[pos] : throw Error("Unexpected end");

        public object? ParseValue()
        {
            switch (Peek())
            {
                case '{': return ParseObject();
                case '[': return ParseArray();
                case '"': return ParseString();
                case 't': Expect("true"); return true;
                case 'f': Expect("false"); return false;
                case 'n': Expect("null"); return null;
                default: return ParseNumber();
            }
        }

        void Expect(string literal)
        {
            if (string.CompareOrdinal(s, pos, literal, 0, literal.Length) != 0)
                throw Error($"Expected '{literal}'");
            pos += literal.Length;
        }

        Dictionary<string, object?> ParseObject()
        {
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            pos++; // {
            SkipWhitespace();
            if (Peek() == '}') { pos++; return result; }
            while (true)
            {
                SkipWhitespace();
                if (Peek() != '"') throw Error("Expected property name");
                var key = ParseString();
                SkipWhitespace();
                if (Peek() != ':') throw Error("Expected ':'");
                pos++;
                SkipWhitespace();
                result[key] = ParseValue();
                SkipWhitespace();
                var c = Peek();
                pos++;
                if (c == '}') return result;
                if (c != ',') throw Error("Expected ',' or '}'");
            }
        }

        List<object?> ParseArray()
        {
            var result = new List<object?>();
            pos++; // [
            SkipWhitespace();
            if (Peek() == ']') { pos++; return result; }
            while (true)
            {
                SkipWhitespace();
                result.Add(ParseValue());
                SkipWhitespace();
                var c = Peek();
                pos++;
                if (c == ']') return result;
                if (c != ',') throw Error("Expected ',' or ']'");
            }
        }

        string ParseString()
        {
            pos++; // opening quote
            var sb = new StringBuilder();
            while (true)
            {
                var c = Peek();
                pos++;
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }

                var e = Peek();
                pos++;
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (pos + 4 > s.Length) throw Error("Truncated \\u escape");
                        sb.Append((char)int.Parse(s.Substring(pos, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        pos += 4;
                        break;
                    default: throw Error($"Invalid escape '\\{e}'");
                }
            }
        }

        object ParseNumber()
        {
            int start = pos;
            while (pos < s.Length && "+-0123456789.eE".IndexOf(s[pos]) >= 0)
                pos++;
            if (start == pos) throw Error("Unexpected character");
            var text = s.Substring(start, pos - start);
            if (long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var l))
                return l;
            if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var d))
                return d;
            throw Error($"Invalid number '{text}'");
        }
    }
}
