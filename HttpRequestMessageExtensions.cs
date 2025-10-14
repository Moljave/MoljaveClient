using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Moljave.Http
{
    public static class HttpRequestMessageExtensions
    {
        private static readonly HttpRequestOptionsKey<MojaveRequestOptions> MojaveOptionsKey =
            new("Mojave.RequestOptions");

        public static async Task<HttpContent> BufferAsync(this HttpContent content)
        {
            if (content == null)
            {
                return null;
            }

            var data = await content.ReadAsByteArrayAsync().ConfigureAwait(false);
            var clone = new ByteArrayContent(data);

            foreach (var header in content.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            clone.Headers.ContentLength = data.Length;
            return clone;
        }

        public static void AddHeaders(this HttpRequestMessage request, string headers)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrWhiteSpace(headers))
            {
                return;
            }

            var lines = headers
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => !string.IsNullOrWhiteSpace(line));

            foreach (var line in lines)
            {
                var separatorIndex = line.IndexOf(':');
                if (separatorIndex <= 0 || separatorIndex == line.Length - 1)
                {
                    continue;
                }

                var key = line[..separatorIndex].Trim();
                var value = line[(separatorIndex + 1)..].Trim();

                if (!request.Headers.TryAddWithoutValidation(key, value))
                {
                    request.Content?.Headers.TryAddWithoutValidation(key, value);
                }
            }
        }

        public static MojaveRequestOptions GetMojaveOptions(this HttpRequestMessage request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return request.Options.TryGetValue(MojaveOptionsKey, out MojaveRequestOptions options)
                ? options
                : null;
        }

        public static void SetMojaveOptions(this HttpRequestMessage request, MojaveRequestOptions options)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (options == null)
            {
                request.Options.Remove(MojaveOptionsKey, out _);
                return;
            }

            request.Options.Set(MojaveOptionsKey, options);
        }

        public static void ConfigureMojaveOptions(this HttpRequestMessage request, Action<MojaveRequestOptions> configure)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (configure == null)
            {
                throw new ArgumentNullException(nameof(configure));
            }

            var options = request.GetMojaveOptions() ?? new MojaveRequestOptions();
            configure(options);
            request.SetMojaveOptions(options);
        }
    }
}
