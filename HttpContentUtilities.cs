using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;

namespace Moljave.Http
{
    internal static class HttpContentUtilities
    {
        public static ByteArrayContent CreateContent(
            ReadOnlyMemory<byte> body,
            IList<KeyValuePair<string, string>> headers,
            out bool wasDecompressed)
        {
            var payload = DecodeBody(body, headers, out wasDecompressed);
            var array = payload.Array ?? Array.Empty<byte>();
            var offset = payload.Offset;
            var count = payload.Count;
            var content = new ByteArrayContent(array, offset, count);

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

            content.Headers.ContentLength = count;
            return content;
        }

        private static ArraySegment<byte> DecodeBody(ReadOnlyMemory<byte> body, IList<KeyValuePair<string, string>> headers, out bool wasDecompressed)
        {
            wasDecompressed = false;

            if (body.IsEmpty || headers == null || headers.Count == 0)
            {
                return GetSegment(body);
            }

            var encodingHeader = headers.FirstOrDefault(h =>
                h.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(encodingHeader.Key))
            {
                return GetSegment(body);
            }

            try
            {
                if (encodingHeader.Value.Contains("gzip", StringComparison.OrdinalIgnoreCase))
                {
                    wasDecompressed = true;
                    return CreateSegment(Decompress(body, stream => new GZipStream(stream, CompressionMode.Decompress)));
                }

                if (encodingHeader.Value.Contains("deflate", StringComparison.OrdinalIgnoreCase))
                {
                    wasDecompressed = true;
                    return CreateSegment(Decompress(body, stream => new DeflateStream(stream, CompressionMode.Decompress)));
                }

                if (encodingHeader.Value.Contains("br", StringComparison.OrdinalIgnoreCase))
                {
                    wasDecompressed = true;
                    return CreateSegment(Decompress(body, stream => new BrotliStream(stream, CompressionMode.Decompress)));
                }
            }
            catch
            {
                wasDecompressed = false;
            }

            return GetSegment(body);
        }

        private static byte[] Decompress(ReadOnlyMemory<byte> body, Func<Stream, Stream> factory)
        {
            var segment = GetSegment(body);
            using var input = new MemoryStream(segment.Array, segment.Offset, segment.Count, writable: false);
            using var decompressor = factory(input);
            using var output = new MemoryStream();
            decompressor.CopyTo(output);
            return output.ToArray();
        }

        private static ArraySegment<byte> GetSegment(ReadOnlyMemory<byte> body)
        {
            if (MemoryMarshal.TryGetArray(body, out ArraySegment<byte> segment))
            {
                return segment;
            }

            var copy = body.ToArray();
            return new ArraySegment<byte>(copy, 0, copy.Length);
        }

        private static ArraySegment<byte> CreateSegment(byte[] array)
            => array == null ? new ArraySegment<byte>(Array.Empty<byte>()) : new ArraySegment<byte>(array, 0, array.Length);
    }
}

