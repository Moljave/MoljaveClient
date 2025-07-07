namespace Moljave.Http
{
    public static class HttpRequestMessageExtensions
    {
        public static async Task<HttpContent> BufferAsync(this HttpContent content)
        {
            if (content == null) return null;
            var data = await content.ReadAsByteArrayAsync();
            var clone = new ByteArrayContent(data);
            foreach (var header in content.Headers)
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            return clone;
        }
        public static void AddHeaders(this HttpRequestMessage request, string headers)
        {
            var parts = headers.Split(Environment.NewLine);
            foreach (var part in parts)
            {
                var key = part.Split(":")[0].Trim();
                var value = part.Split($"{key}:")[1].Trim();
                request.Headers.TryAddWithoutValidation(key, value);
            }
        }
    }
}
