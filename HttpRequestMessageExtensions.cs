namespace Moljave.Http
{
    public static class HttpRequestMessageExtensions
    {
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
