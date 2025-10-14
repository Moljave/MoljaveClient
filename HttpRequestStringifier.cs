using System;
using System.Net;
using System.Net.Http;
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

            var builder = new StringBuilder();
            builder.Append(request.Method.Method);
            builder.Append(' ');
            builder.Append(target);
            builder.Append(" HTTP/1.1\r\n");

            var hostHeader = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
            if (!request.Headers.Contains("Host"))
            {
                builder.Append("Host: ");
                builder.Append(hostHeader);
                builder.Append("\r\n");
            }

            foreach (var header in request.Headers)
            {
                builder.Append(header.Key);
                builder.Append(':');
                builder.Append(' ');
                builder.Append(string.Join(", ", header.Value));
                builder.Append("\r\n");
            }

            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers)
                {
                    builder.Append(header.Key);
                    builder.Append(':');
                    builder.Append(' ');
                    builder.Append(string.Join(", ", header.Value));
                    builder.Append("\r\n");
                }
            }

            builder.Append("\r\n");

            var headerBytes = Encoding.ASCII.GetBytes(builder.ToString());
            if (contentBytes.Length == 0)
            {
                return headerBytes;
            }

            var result = new byte[headerBytes.Length + contentBytes.Length];
            Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
            Buffer.BlockCopy(contentBytes, 0, result, headerBytes.Length, contentBytes.Length);
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

            var newRequest = new HttpRequestMessage(newMethod, newUri);

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
    }
}
