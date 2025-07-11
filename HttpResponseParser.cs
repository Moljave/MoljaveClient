﻿using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.IO.Compression;
using System.Text;

namespace Moljave.Http
{
    public static class HttpResponseParser
    {
        public static HttpResponseMessage Parse(byte[] responseBytes)
        {
            var httpResponse = new HttpResponseMessage();
            string contentEncoding = null;

            int headerEnd = -1;
            for (int i = 0; i < responseBytes.Length - 3; i++)
            {
                if (responseBytes[i] == 13 && responseBytes[i + 1] == 10 &&
                    responseBytes[i + 2] == 13 && responseBytes[i + 3] == 10)
                {
                    headerEnd = i + 4;
                    break;
                }
            }

            if (headerEnd == -1)
                throw new Exception("Failed to find header/body separator");

            string headerText = System.Text.Encoding.ASCII.GetString(responseBytes, 0, headerEnd);
            using (var sr = new System.IO.StringReader(headerText))
            {
                var statusLine = sr.ReadLine();
                if (statusLine != null)
                {
                    var statusLineParts = statusLine.Split(' ');
                    if (statusLineParts.Length >= 3)
                        httpResponse.StatusCode = (HttpStatusCode)Enum.Parse(typeof(HttpStatusCode), statusLineParts[1]);
                }

                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                        break;

                    var headerParts = line.Split(new[] { ':' }, 2);
                    if (headerParts.Length == 2)
                    {
                        var headerKey = headerParts[0].Trim();
                        var headerValue = headerParts[1].Trim();
                        httpResponse.Headers.TryAddWithoutValidation(headerKey, headerValue);

                        if (headerKey.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase))
                            contentEncoding = headerValue.ToLower();
                    }
                }
            }

            byte[] bodyBytes = responseBytes.Skip(headerEnd).ToArray();

            string bodyString = string.Empty;

            if (bodyBytes.Length > 0 && !string.IsNullOrEmpty(contentEncoding))
            {
                try
                {
                    if (contentEncoding.Contains("gzip"))
                    {
                        using (var ms = new System.IO.MemoryStream(bodyBytes))
                        using (var gzip = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress))
                        using (var reader = new System.IO.StreamReader(gzip))
                            bodyString = reader.ReadToEnd();
                    }
                    else if (contentEncoding.Contains("deflate"))
                    {
                        using (var ms = new System.IO.MemoryStream(bodyBytes))
                        using (var deflate = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress))
                        using (var reader = new System.IO.StreamReader(deflate))
                            bodyString = reader.ReadToEnd();
                    }
                    else if (contentEncoding.Contains("br"))
                    {
                        using (var ms = new System.IO.MemoryStream(bodyBytes))
                        using (var br = new System.IO.Compression.BrotliStream(ms, System.IO.Compression.CompressionMode.Decompress))
                        using (var reader = new System.IO.StreamReader(br))
                            bodyString = reader.ReadToEnd();
                    }
                    else
                    {
                        bodyString = System.Text.Encoding.UTF8.GetString(bodyBytes);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to decompress response: " + ex.Message);
                    bodyString = System.Text.Encoding.UTF8.GetString(bodyBytes);
                }
            }
            else if (bodyBytes.Length > 0)
            {
                // no encoding, just text or binary
                bodyString = System.Text.Encoding.UTF8.GetString(bodyBytes);
            }
            else
            {
                // No body at all
                bodyString = string.Empty;
            }

            httpResponse.Content = new StringContent(bodyString);

            return httpResponse;
        }
    }
}
