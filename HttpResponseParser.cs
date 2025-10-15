using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Moljave.Http
{
    public static class HttpResponseParser
    {
        public static HttpResponseMessage Parse(byte[] responseBytes)
        {
            if (responseBytes == null || responseBytes.Length == 0)
            {
                throw new ArgumentException("Response bytes cannot be null or empty.", nameof(responseBytes));
            }

            var separator = FindHeaderBodySeparator(responseBytes);
            if (separator < 0)
            {
                throw new InvalidOperationException("Failed to locate HTTP header terminator.");
            }

            var headerBytes = responseBytes[..separator];
            var bodyBytes = responseBytes[separator..];
            var headerText = Encoding.ASCII.GetString(headerBytes);

            using var reader = new StringReader(headerText);
            var statusLine = reader.ReadLine();
            if (string.IsNullOrEmpty(statusLine))
            {
                throw new InvalidOperationException("Invalid HTTP response: missing status line.");
            }

            var statusParts = statusLine.Split(' ');
            if (statusParts.Length < 2)
            {
                throw new InvalidOperationException("Invalid HTTP status line.");
            }

            var response = new HttpResponseMessage
            {
                StatusCode = (HttpStatusCode)int.Parse(statusParts[1]),
            };

            if (statusParts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) &&
                Version.TryParse(statusParts[0][5..], out var version))
            {
                response.Version = version;
            }

            if (statusParts.Length > 2)
            {
                response.ReasonPhrase = string.Join(' ', statusParts.Skip(2));
            }

            var contentHeaders = new List<KeyValuePair<string, string>>();
            string line;
            while (!string.IsNullOrEmpty(line = reader.ReadLine()))
            {
                var separatorIndex = line.IndexOf(':');
                if (separatorIndex <= 0)
                {
                    continue;
                }

                var name = line[..separatorIndex].Trim();
                var value = line[(separatorIndex + 1)..].Trim();

                if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                {
                    contentHeaders.Add(new KeyValuePair<string, string>(name, value));
                }
                else
                {
                    response.Headers.TryAddWithoutValidation(name, value);
                }
            }

            response.Content = HttpContentUtilities.CreateContent(bodyBytes, contentHeaders, out _);
            return response;
        }

        private static int FindHeaderBodySeparator(byte[] responseBytes)
        {
            for (int i = 0; i < responseBytes.Length - 3; i++)
            {
                if (responseBytes[i] == 13 && responseBytes[i + 1] == 10 &&
                    responseBytes[i + 2] == 13 && responseBytes[i + 3] == 10)
                {
                    return i + 4;
                }
            }

            return -1;
        }
    }
}
