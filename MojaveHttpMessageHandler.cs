using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    internal sealed class MojaveHttpMessageHandler : HttpMessageHandler
    {
        private readonly MojaveHttpClientOptions _options;
        private readonly object _cookieLock = new();

        public MojaveHttpMessageHandler(MojaveHttpClientOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return SendAsyncInternal(request, cancellationToken, 0);
        }

        private async Task<HttpResponseMessage> SendAsyncInternal(HttpRequestMessage request, CancellationToken cancellationToken, int redirectCount)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var uri = request.RequestUri ?? throw new InvalidOperationException("RequestUri is required");
            var useTls = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

            var requestOptions = request.GetMojaveOptions()?.Clone() ?? new MojaveRequestOptions();

            var effectiveTimeout = requestOptions.Timeout ?? _options.DefaultTimeout;
            var allowRedirect = requestOptions.AllowAutoRedirect ?? _options.AllowAutoRedirect;
            var maxRedirects = requestOptions.MaxAutomaticRedirections ?? _options.MaxAutomaticRedirections;
            var cookieContainer = requestOptions.CookieContainer ?? _options.CookieContainer;
            var fingerprint = requestOptions.Fingerprint ?? _options.FingerprintProvider?.Invoke() ?? JA3Fingerprint.Default;
            var tlsSettings = requestOptions.TlsSettings ?? _options.TlsSettingsProvider?.Invoke() ?? MojaveTlsSettings.Default;
            var proxyOptions = requestOptions.Proxy ?? _options.ProxyResolver?.Invoke() ?? MojaveProxyOptions.NoProxy;

            if (request.Content != null)
            {
                request.Content = await request.Content.BufferAsync().ConfigureAwait(false);
            }

            if (!request.Headers.Contains("Accept-Encoding"))
            {
                request.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br");
            }

            if (cookieContainer != null)
            {
                string cookieHeader;
                lock (_cookieLock)
                {
                    cookieHeader = cookieContainer.GetCookieHeader(uri);
                }

                if (!string.IsNullOrEmpty(cookieHeader))
                {
                    request.Headers.Remove("Cookie");
                    request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
                }
            }

            var requestPayload = await HttpRequestStringifier.Stringify(request).ConfigureAwait(false);

            using var tlsClient = new TlsClient(
                uri.Host,
                uri.IsDefaultPort ? (useTls ? 443 : 80) : uri.Port,
                fingerprint,
                proxyOptions?.Descriptor,
                tlsSettings,
                _options.CertificateValidationCallback);

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linkedCts.CancelAfter(effectiveTimeout);

            var responseBytes = await tlsClient.SendRequestAsync(
                requestPayload,
                linkedCts.Token,
                useTls).ConfigureAwait(false);

            var response = HttpResponseParser.Parse(responseBytes);

            if (cookieContainer != null && response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
            {
                lock (_cookieLock)
                {
                    foreach (var cookie in setCookieHeaders)
                    {
                        cookieContainer.SetCookies(uri, cookie);
                    }
                }
            }

            if (allowRedirect && IsRedirect(response.StatusCode))
            {
                if (redirectCount >= maxRedirects)
                {
                    throw new HttpRequestException("Maximum automatic redirections exceeded.");
                }

                var location = response.Headers.Location;
                if (location != null)
                {
                    var newUri = location.IsAbsoluteUri ? location : new Uri(uri, location);
                    var newRequest = await HttpRequestStringifier.CloneWithRedirectAsync(
                        request,
                        newUri,
                        response.StatusCode).ConfigureAwait(false);
                    newRequest.SetMojaveOptions(request.GetMojaveOptions()?.Clone());
                    response.Dispose();
                    return await SendAsyncInternal(newRequest, cancellationToken, redirectCount + 1).ConfigureAwait(false);
                }
            }

            return response;
        }

        private static bool IsRedirect(HttpStatusCode statusCode)
        {
            return statusCode == HttpStatusCode.Moved ||
                   statusCode == HttpStatusCode.Redirect ||
                   statusCode == HttpStatusCode.RedirectMethod ||
                   statusCode == HttpStatusCode.TemporaryRedirect ||
                   (int)statusCode == 308;
        }
    }
}
