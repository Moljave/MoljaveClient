using System.Net.Http;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Moljave.Http
{
    public static class HttpRequestStringifier
    {
        public static async Task<string> Stringify(HttpRequestMessage request)
        {
            var sb = new StringBuilder();

            sb.AppendLine($"{request.Method} {request.RequestUri.PathAndQuery} HTTP/1.1");
            sb.AppendLine($"Host: {request.RequestUri.Host}");

            foreach (var header in request.Headers)
                sb.AppendLine($"{header.Key}: {string.Join(", ", header.Value)}");

            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers)
                    sb.AppendLine($"{header.Key}: {string.Join(", ", header.Value)}");
            }

            sb.AppendLine();

            if (request.Content != null)
            {
                var body = await request.Content.ReadAsStringAsync();
                sb.Append(body);
            }

            return sb.ToString();
        }

        public static HttpRequestMessage CloneWithRedirect(HttpRequestMessage oldRequest, Uri newUri, HttpStatusCode redirectStatus)
        {
            var newMethod = oldRequest.Method;
            if (redirectStatus == HttpStatusCode.SeeOther ||
                ((redirectStatus == HttpStatusCode.MovedPermanently || redirectStatus == HttpStatusCode.Redirect) && oldRequest.Method == HttpMethod.Post))
            {
                newMethod = HttpMethod.Get;
            }

            var newRequest = new HttpRequestMessage(newMethod, newUri);

            foreach (var header in oldRequest.Headers)
            {
                if (header.Key.Equals("Host", System.StringComparison.OrdinalIgnoreCase)) continue;
                try { newRequest.Headers.TryAddWithoutValidation(header.Key, header.Value); }
                catch { }
            }

            if (newMethod == HttpMethod.Post || newMethod == HttpMethod.Put || newMethod == HttpMethod.Patch)
                newRequest.Content = oldRequest.Content;

            return newRequest;
        }
    }
}
