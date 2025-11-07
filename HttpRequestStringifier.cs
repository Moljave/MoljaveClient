using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Moljave.Http
{
    public static class HttpRequestStringifier
    {
        public static async Task<byte[]> Stringify(HttpRequestMessage request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var uri = request.RequestUri ?? throw new InvalidOperationException("RequestUri cannot be null");
            var target = uri.PathAndQuery;
            if (string.IsNullOrEmpty(target))
            {
                target = "/";
            }

            if (!string.IsNullOrEmpty(uri.Fragment))
            {
                target += uri.Fragment;
            }

            byte[] contentBytes = Array.Empty<byte>();
            if (request.Content != null)
            {
                contentBytes = await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                request.Content.Headers.ContentLength = contentBytes.Length;
            }

            var writer = new ArrayBufferWriter<byte>(512);

            void WriteAscii(string value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    return;
                }

                var span = writer.GetSpan(value.Length);
                var written = Encoding.ASCII.GetBytes(value.AsSpan(), span);
                writer.Advance(written);
            }

            void WriteCrlf()
            {
                var span = writer.GetSpan(2);
                span[0] = (byte)'\r';
                span[1] = (byte)'\n';
                writer.Advance(2);
            }

            void WriteHeader(string name, IEnumerable<string> values)
            {
                if (values == null)
                {
                    return;
                }

                WriteAscii(name);
                WriteAscii(": ");

                bool first = true;
                foreach (var value in values)
                {
                    if (!first)
                    {
                        WriteAscii(", ");
                    }

                    first = false;
                    if (!string.IsNullOrEmpty(value))
                    {
                        WriteAscii(value);
                    }
                }

                WriteCrlf();
            }

            WriteAscii(request.Method.Method);
            WriteAscii(" ");
            WriteAscii(target);
            WriteAscii(" HTTP/1.1");
            WriteCrlf();

            var hostHeader = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
            if (!request.Headers.Contains("Host"))
            {
                WriteHeader("Host", new[] { hostHeader });
            }

            foreach (var header in request.Headers)
            {
                WriteHeader(header.Key, header.Value);
            }

            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers)
                {
                    WriteHeader(header.Key, header.Value);
                }
            }

            WriteCrlf();

            var headers = writer.WrittenMemory;
            if (contentBytes.Length == 0)
            {
                return headers.ToArray();
            }

            var result = new byte[headers.Length + contentBytes.Length];
            headers.Span.CopyTo(result);
            Buffer.BlockCopy(contentBytes, 0, result, headers.Length, contentBytes.Length);
            return result;
        }

        public static async Task<HttpRequestMessage> CloneWithRedirectAsync(
            HttpRequestMessage oldRequest,
            Uri newUri,
            HttpStatusCode redirectStatus)
        {
            if (oldRequest == null)
            {
                throw new ArgumentNullException(nameof(oldRequest));
            }

            if (newUri == null)
            {
                throw new ArgumentNullException(nameof(newUri));
            }

            var newMethod = oldRequest.Method;
            if (redirectStatus == HttpStatusCode.SeeOther ||
                ((redirectStatus == HttpStatusCode.Moved || redirectStatus == HttpStatusCode.Redirect) && oldRequest.Method == HttpMethod.Post))
            {
                newMethod = HttpMethod.Get;
            }

            var newRequest = new HttpRequestMessage(newMethod, newUri)
            {
                Version = oldRequest.Version
            };

            CopyVersionPolicy(oldRequest, newRequest);

            foreach (var header in oldRequest.Headers)
            {
                if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                newRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (oldRequest.Content != null && newMethod != HttpMethod.Get && newMethod != HttpMethod.Head)
            {
                newRequest.Content = await oldRequest.Content.BufferAsync().ConfigureAwait(false);
            }

            return newRequest;
        }

        internal static void CopyVersionPolicy(HttpRequestMessage source, HttpRequestMessage destination)
        {
            var versionPolicyProperty = typeof(HttpRequestMessage).GetProperty("VersionPolicy");
            if (versionPolicyProperty == null)
            {
                return;
            }

            var value = versionPolicyProperty.GetValue(source);
            versionPolicyProperty.SetValue(destination, value);
        }
    }
}
