using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;

namespace Moljave.Http
{
    public static class HttpResponseParser
    {
        public static HttpResponseMessage Parse(ReadOnlySpan<byte> headerSpan, ReadOnlyMemory<byte> bodyMemory)
        {
            if (headerSpan.IsEmpty)
            {
                throw new ArgumentException("Response header cannot be empty.", nameof(headerSpan));
            }

            var statusLineEnd = headerSpan.IndexOf((byte)'\n');
            if (statusLineEnd < 0)
            {
                throw new InvalidOperationException("Invalid HTTP response: missing status line terminator.");
            }

            var statusLine = TrimHeaderLine(headerSpan.Slice(0, statusLineEnd + 1));
            if (statusLine.Length == 0)
            {
                throw new InvalidOperationException("Invalid HTTP response: missing status line.");
            }

            var response = ParseStatusLine(statusLine);

            var contentHeaders = new List<KeyValuePair<string, string>>();
            var offset = statusLineEnd + 1;

            while (offset < headerSpan.Length)
            {
                var remaining = headerSpan.Slice(offset);
                var lineEnd = remaining.IndexOf((byte)'\n');
                if (lineEnd < 0)
                {
                    break;
                }

                var rawLine = remaining.Slice(0, lineEnd + 1);
                offset += lineEnd + 1;

                var line = TrimHeaderLine(rawLine);
                if (line.Length == 0)
                {
                    continue;
                }

                var separatorIndex = line.IndexOf((byte)':');
                if (separatorIndex <= 0)
                {
                    continue;
                }

                var nameSpan = line.Slice(0, separatorIndex);
                var valueSpan = TrimAsciiWhitespace(line.Slice(separatorIndex + 1));

                var name = Encoding.ASCII.GetString(nameSpan);
                var value = Encoding.ASCII.GetString(valueSpan);

                if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                {
                    contentHeaders.Add(new KeyValuePair<string, string>(name, value));
                }
                else
                {
                    response.Headers.TryAddWithoutValidation(name, value);
                }
            }

            response.Content = HttpContentUtilities.CreateContent(bodyMemory, contentHeaders, out _);
            return response;
        }

        private static HttpResponseMessage ParseStatusLine(ReadOnlySpan<byte> statusLine)
        {
            var firstSpace = statusLine.IndexOf((byte)' ');
            if (firstSpace <= 0)
            {
                throw new InvalidOperationException("Invalid HTTP status line.");
            }

            var protocolSpan = statusLine.Slice(0, firstSpace);
            var remainder = TrimAsciiWhitespace(statusLine.Slice(firstSpace + 1));

            var secondSpace = remainder.IndexOf((byte)' ');
            ReadOnlySpan<byte> statusCodeSpan;
            ReadOnlySpan<byte> reasonPhraseSpan;

            if (secondSpace >= 0)
            {
                statusCodeSpan = remainder.Slice(0, secondSpace);
                reasonPhraseSpan = TrimAsciiWhitespace(remainder.Slice(secondSpace + 1));
            }
            else
            {
                statusCodeSpan = remainder;
                reasonPhraseSpan = ReadOnlySpan<byte>.Empty;
            }

            if (!Utf8Parser.TryParse(statusCodeSpan, out int statusCode, out int consumed) || consumed != statusCodeSpan.Length)
            {
                throw new InvalidOperationException("Invalid HTTP status code in response.");
            }

            var response = new HttpResponseMessage
            {
                StatusCode = (HttpStatusCode)statusCode
            };

            if (protocolSpan.Length >= 5 && EqualsAsciiIgnoreCase(protocolSpan.Slice(0, 5), "HTTP/"))
            {
                var versionSpan = protocolSpan.Slice(5);
                if (versionSpan.Length > 0)
                {
                    var versionText = Encoding.ASCII.GetString(versionSpan);
                    if (Version.TryParse(versionText, out var version))
                    {
                        response.Version = version;
                    }
                }
            }

            if (!reasonPhraseSpan.IsEmpty)
            {
                response.ReasonPhrase = Encoding.ASCII.GetString(reasonPhraseSpan);
            }

            return response;
        }

        private static ReadOnlySpan<byte> TrimHeaderLine(ReadOnlySpan<byte> value)
        {
            int start = 0;
            int end = value.Length;

            while (start < end && (value[start] == (byte)'\r' || value[start] == (byte)'\n'))
            {
                start++;
            }

            while (end > start && (value[end - 1] == (byte)'\r' || value[end - 1] == (byte)'\n'))
            {
                end--;
            }

            return value.Slice(start, end - start);
        }

        private static ReadOnlySpan<byte> TrimAsciiWhitespace(ReadOnlySpan<byte> value)
        {
            int start = 0;
            int end = value.Length;

            while (start < end && IsAsciiWhitespace(value[start]))
            {
                start++;
            }

            while (end > start && IsAsciiWhitespace(value[end - 1]))
            {
                end--;
            }

            return value.Slice(start, end - start);
        }

        private static bool IsAsciiWhitespace(byte value)
        {
            return value == (byte)' ' || value == (byte)'\t' || value == (byte)'\r' || value == (byte)'\n';
        }

        private static bool EqualsAsciiIgnoreCase(ReadOnlySpan<byte> span, string value)
        {
            if (value == null || span.Length != value.Length)
            {
                return false;
            }

            for (int i = 0; i < value.Length; i++)
            {
                var source = ToLowerAscii(span[i]);
                var target = ToLowerAscii((byte)value[i]);
                if (source != target)
                {
                    return false;
                }
            }

            return true;
        }

        private static byte ToLowerAscii(byte value)
        {
            if ((uint)(value - 'A') <= ('Z' - 'A'))
            {
                return (byte)(value | 0x20);
            }

            return value;
        }
    }
}
