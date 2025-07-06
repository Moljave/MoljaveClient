using System;
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

            string headerText = Encoding.ASCII.GetString(responseBytes, 0, headerEnd);
            using (var sr = new StringReader(headerText))
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

            string bodyString;
            if (!string.IsNullOrEmpty(contentEncoding) && bodyBytes.Length > 0)
            {
                try
                {
                    if (contentEncoding.Contains("gzip"))
                    {
                        using (var ms = new MemoryStream(bodyBytes))
                        using (var gzip = new GZipStream(ms, CompressionMode.Decompress))
                        using (var reader = new StreamReader(gzip))
                            bodyString = reader.ReadToEnd();
                    }
                    else if (contentEncoding.Contains("deflate"))
                    {
                        using (var ms = new MemoryStream(bodyBytes))
                        using (var deflate = new DeflateStream(ms, CompressionMode.Decompress))
                        using (var reader = new StreamReader(deflate))
                            bodyString = reader.ReadToEnd();
                    }
                    else if (contentEncoding.Contains("br"))
                    {
                        using (var ms = new MemoryStream(bodyBytes))
                        using (var br = new BrotliStream(ms, CompressionMode.Decompress))
                        using (var reader = new StreamReader(br))
                            bodyString = reader.ReadToEnd();
                    }
                    else
                    {
                        bodyString = Encoding.UTF8.GetString(bodyBytes);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to decompress response: " + ex.Message);
                    bodyString = Encoding.UTF8.GetString(bodyBytes);
                }
            }
            else
            {
                bodyString = Encoding.UTF8.GetString(bodyBytes);
            }

            httpResponse.Content = new StringContent(bodyString);

            return httpResponse;
        }
    }
}
