using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;

namespace Moljave.Http
{
    internal static class HttpContentUtilities
    {
        public static ByteArrayContent CreateContent(
            byte[] body,
            IList<KeyValuePair<string, string>> headers,
            out bool wasDecompressed)
        {
            var payload = DecodeBody(body, headers, out wasDecompressed);
            var content = new ByteArrayContent(payload);

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (wasDecompressed && header.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            content.Headers.ContentLength = payload.LongLength;
            return content;
        }

        private static byte[] DecodeBody(byte[] body, IList<KeyValuePair<string, string>> headers, out bool wasDecompressed)
        {
            wasDecompressed = false;

            if (body == null || body.Length == 0 || headers == null || headers.Count == 0)
            {
                return body ?? Array.Empty<byte>();
            }

            var encodingHeader = headers.FirstOrDefault(h =>
                h.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(encodingHeader.Key))
            {
                return body;
            }

            try
            {
                if (encodingHeader.Value.Contains("gzip", StringComparison.OrdinalIgnoreCase))
                {
                    wasDecompressed = true;
                    return Decompress(body, stream => new GZipStream(stream, CompressionMode.Decompress));
                }

                if (encodingHeader.Value.Contains("deflate", StringComparison.OrdinalIgnoreCase))
                {
                    wasDecompressed = true;
                    return Decompress(body, stream => new DeflateStream(stream, CompressionMode.Decompress));
                }

                if (encodingHeader.Value.Contains("br", StringComparison.OrdinalIgnoreCase))
                {
                    wasDecompressed = true;
                    return Decompress(body, stream => new BrotliStream(stream, CompressionMode.Decompress));
                }
            }
            catch
            {
                wasDecompressed = false;
            }

            return body;
        }

        private static byte[] Decompress(byte[] body, Func<Stream, Stream> factory)
        {
            using var input = new MemoryStream(body);
            using var decompressor = factory(input);
            using var output = new MemoryStream();
            decompressor.CopyTo(output);
            return output.ToArray();
        }
    }
}

