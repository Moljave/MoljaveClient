using Moljave.Http;
using System.Net;

namespace Moljave.Http
{
    public class MojaveHttpClient : IDisposable
    {
        private TlsClient _tlsClient;
        private JA3Fingerprint _ja3Fingerprint;
        private readonly CookieContainer _cookieContainer;
        private readonly WebProxy _proxy;
        public bool AllowAutoRedirect { get; set; } = true;
        public int MaxAutomaticRedirections { get; set; } = 10;

        private string _lastHost = null;
        private int _lastPort = -1;

        public MojaveHttpClient(
            JA3Fingerprint ja3Fingerprint = null,
            CookieContainer cookieContainer = null,
            WebProxy proxy = null)
        {
            _cookieContainer = cookieContainer ?? new CookieContainer();
            _proxy = proxy;
            _ja3Fingerprint = ja3Fingerprint ?? JA3Fingerprint.Default;
        }

        public void Dispose() => _tlsClient?.Dispose();

        public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, TimeSpan timeout)
        {
            // Буферизация тела запроса (важно для POST/PUT/PATCH/DELETE)
            if (request.Content != null)
                request.Content = await request.Content.BufferAsync();

            return await SendAsyncInternal(request, timeout, 0);
        }

        private async Task<HttpResponseMessage> SendAsyncInternal(HttpRequestMessage request, TimeSpan timeout, int redirectCount)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            var uri = request.RequestUri ?? throw new ArgumentNullException("RequestUri");
            var host = uri.Host;
            var port = uri.Port > 0 ? uri.Port : 443;

            if (_tlsClient == null || !(_lastHost?.Equals(host, StringComparison.OrdinalIgnoreCase) ?? false) || _lastPort != port)
            {
                _tlsClient?.Dispose();
                _tlsClient = new TlsClient(host, port, _ja3Fingerprint, _proxy);
                _lastHost = host;
                _lastPort = port;
            }

            if (!request.Headers.Contains("Accept-Encoding"))
                request.Headers.Add("Accept-Encoding", "gzip, deflate, br");

            string cookieHeader = _cookieContainer.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                request.Headers.Remove("Cookie");
                request.Headers.Add("Cookie", cookieHeader);
            }

            var requestString = await HttpRequestStringifier.Stringify(request);
            var responseBytes = await _tlsClient.SendRequestAsync(requestString, timeout);
            var response = HttpResponseParser.Parse(responseBytes);

            if (response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
            {
                foreach (var setCookieHeader in setCookieHeaders)
                    _cookieContainer.SetCookies(uri, setCookieHeader);
            }

            if (AllowAutoRedirect && IsRedirect(response.StatusCode))
            {
                if (redirectCount >= MaxAutomaticRedirections)
                    throw new Exception("Maximum redirection count exceeded.");

                if (response.Headers.Location != null)
                {
                    var newUri = response.Headers.Location.IsAbsoluteUri
                        ? response.Headers.Location
                        : new Uri(uri, response.Headers.Location);

                    // Клонируем и буферизуем новый запрос для редиректа
                    var newRequest = await HttpRequestStringifier.CloneWithRedirectAsync(request, newUri, response.StatusCode);
                    response.Dispose();
                    return await SendAsyncInternal(newRequest, timeout, redirectCount + 1);
                }
            }

            return response;
        }

        private bool IsRedirect(HttpStatusCode code) =>
            code == HttpStatusCode.MovedPermanently ||
            code == HttpStatusCode.Redirect ||
            code == HttpStatusCode.RedirectMethod ||
            code == HttpStatusCode.TemporaryRedirect ||
            (int)code == 308;
    }
}
