using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    internal sealed class MojaveHttpMessageHandler : HttpMessageHandler
    {
        private readonly MojaveHttpClientOptions _options;
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

            var currentRequest = request;
            var currentRedirectCount = redirectCount;

            while (true)
            {
                var uri = currentRequest.RequestUri ?? throw new InvalidOperationException("RequestUri is required");
                var useTls = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

                var requestOptions = currentRequest.GetMojaveOptions();
                var effectiveTimeout = requestOptions?.Timeout ?? _options.DefaultTimeout;
                var maxRedirects = requestOptions?.MaxAutomaticRedirections ?? _options.MaxAutomaticRedirections;
                var cookieManager = requestOptions?.CookieManager ?? _options.CookieManager;
                var fingerprint = requestOptions?.Fingerprint ?? _options.FingerprintProvider?.Invoke() ?? JA3Fingerprint.Default;
                var tlsSettings = requestOptions?.TlsSettings ?? _options.TlsSettingsProvider?.Invoke() ?? MojaveTlsSettings.Default;
                var proxyOptions = requestOptions?.Proxy ?? _options.ProxyResolver?.Invoke() ?? MojaveProxyOptions.NoProxy;

                if (currentRequest.Content != null)
                {
                    currentRequest.Content = await currentRequest.Content.BufferAsync().ConfigureAwait(false);
                }

                if (!currentRequest.Headers.Contains("Accept-Encoding"))
                {
                    currentRequest.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br");
                }

                if (cookieManager != null)
                {
                    var cookieHeader = cookieManager.GetCookieHeader(uri);
                    if (!string.IsNullOrEmpty(cookieHeader))
                    {
                        currentRequest.Headers.Remove("Cookie");
                        currentRequest.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
                    }
                }

                HttpResponseMessage response = ShouldUseHttp2(currentRequest)
                    ? await SendHttp2Async(currentRequest, uri, effectiveTimeout, fingerprint, tlsSettings, proxyOptions, cancellationToken).ConfigureAwait(false)
                    : await SendHttp11Async(currentRequest, uri, useTls, effectiveTimeout, fingerprint, tlsSettings, proxyOptions, cancellationToken).ConfigureAwait(false);

                if (cookieManager != null && response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
                {
                    cookieManager.UpdateFromSetCookieHeaders(uri, setCookieHeaders);
                }

                var redirectOptions = currentRequest.GetMojaveOptions();
                var allowRedirect = (redirectOptions?.AllowAutoRedirect ?? requestOptions?.AllowAutoRedirect ?? _options.AllowAutoRedirect);

                if (!allowRedirect || !IsRedirect(response.StatusCode))
                {
                    return response;
                }

                var redirectLimit = redirectOptions?.MaxAutomaticRedirections ?? maxRedirects;
                if (currentRedirectCount >= redirectLimit)
                {
                    response.Dispose();
                    throw new HttpRequestException("Maximum automatic redirections exceeded.");
                }

                var location = response.Headers.Location;
                if (location == null)
                {
                    return response;
                }

                var newUri = location.IsAbsoluteUri ? location : new Uri(uri, location);
                var newRequest = await HttpRequestStringifier.CloneWithRedirectAsync(currentRequest, newUri, response.StatusCode).ConfigureAwait(false);

                if (redirectOptions != null)
                {
                    newRequest.SetMojaveOptions(redirectOptions);
                }
                else
                {
                    newRequest.SetMojaveOptions(null);
                }

                response.Dispose();
                currentRequest = newRequest;
                currentRedirectCount++;
            }
        }

        private static bool IsRedirect(HttpStatusCode statusCode)
        {
            return statusCode == HttpStatusCode.Moved ||
                   statusCode == HttpStatusCode.Redirect ||
                   statusCode == HttpStatusCode.RedirectMethod ||
                   statusCode == HttpStatusCode.TemporaryRedirect ||
                   (int)statusCode == 308;
        }

        private static bool ShouldUseHttp2(HttpRequestMessage request)
        {
            if (request?.Version == null)
            {
                return false;
            }

            return request.Version.Major >= 2;
        }

        private async Task<HttpResponseMessage> SendHttp11Async(
            HttpRequestMessage request,
            Uri uri,
            bool useTls,
            TimeSpan timeout,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            MojaveProxyOptions proxyOptions,
            CancellationToken cancellationToken)
        {
            var requestPayload = await HttpRequestStringifier.Stringify(request).ConfigureAwait(false);

            using var tlsClient = new TlsClient(
                uri.Host,
                uri.IsDefaultPort ? (useTls ? 443 : 80) : uri.Port,
                fingerprint,
                proxyOptions?.Descriptor,
                tlsSettings,
                _options.CertificateValidationCallback);

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (timeout > TimeSpan.Zero)
            {
                linkedCts.CancelAfter(timeout);
            }

            try
            {
                var responseBytes = await tlsClient.SendRequestAsync(requestPayload, linkedCts.Token, useTls).ConfigureAwait(false);
                var response = HttpResponseParser.Parse(responseBytes);
                response.RequestMessage = request;
                return response;
            }
            catch (OperationCanceledException) when (linkedCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("The HTTP/1.1 request timed out.");
            }
        }

        private async Task<HttpResponseMessage> SendHttp2Async(
            HttpRequestMessage request,
            Uri uri,
            TimeSpan timeout,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            MojaveProxyOptions proxyOptions,
            CancellationToken cancellationToken)
        {
            using var handler = CreateHttp2Handler(uri, fingerprint, tlsSettings, proxyOptions);
            using var invoker = new HttpMessageInvoker(handler, disposeHandler: true);
            var http2Request = await CloneHttpRequestForHttp2Async(request).ConfigureAwait(false);

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (timeout > TimeSpan.Zero)
            {
                linkedCts.CancelAfter(timeout);
            }

            try
            {
                var response = await invoker.SendAsync(http2Request, linkedCts.Token).ConfigureAwait(false);

                using (response)
                {
                    var bodyBytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                    var finalResponse = new HttpResponseMessage(response.StatusCode)
                    {
                        Version = response.Version,
                        ReasonPhrase = response.ReasonPhrase,
                        RequestMessage = request
                    };

                    foreach (var header in response.Headers)
                    {
                        finalResponse.Headers.TryAddWithoutValidation(header.Key, header.Value);
                    }

                    var contentHeaders = new List<KeyValuePair<string, string>>();
                    foreach (var header in response.Content.Headers)
                    {
                        contentHeaders.Add(new KeyValuePair<string, string>(header.Key, string.Join(", ", header.Value)));
                    }

                    finalResponse.Content = HttpContentUtilities.CreateContent(bodyBytes, contentHeaders, out _);
                    return finalResponse;
                }
            }
            catch (OperationCanceledException) when (linkedCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("The HTTP/2 request timed out.");
            }
        }

        private async Task<HttpRequestMessage> CloneHttpRequestForHttp2Async(HttpRequestMessage request)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri)
            {
                Version = request.Version
            };

            HttpRequestStringifier.CopyVersionPolicy(request, clone);

            foreach (var header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (request.Content != null)
            {
                clone.Content = await request.Content.BufferAsync().ConfigureAwait(false);
                foreach (var header in request.Content.Headers)
                {
                    clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            return clone;
        }

        private HttpMessageHandler CreateHttp2Handler(
            Uri uri,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            MojaveProxyOptions proxyOptions)
        {
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                UseCookies = false,
                EnableMultipleHttp2Connections = true
            };

            handler.SslOptions = BuildHttp2SslOptions(uri.Host, fingerprint, tlsSettings);

            if (proxyOptions?.Descriptor != null)
            {
                switch (proxyOptions.Descriptor.Scheme)
                {
                    case ProxyScheme.Http:
                    case ProxyScheme.Https:
                        handler.Proxy = proxyOptions.Descriptor.ToWebProxy();
                        handler.UseProxy = true;
                        break;
                    default:
                        handler.UseProxy = false;
                        handler.ConnectCallback = async (context, token) =>
                        {
                            var connector = new TlsClient(
                                context.DnsEndPoint.Host,
                                context.DnsEndPoint.Port,
                                fingerprint,
                                proxyOptions.Descriptor,
                                tlsSettings,
                                _options.CertificateValidationCallback);

                            var stream = await connector.CreateTransportStreamAsync(token).ConfigureAwait(false);
                            return new TlsClientTransportStream(connector, stream);
                        };
                        break;
                }
            }
            else
            {
                handler.UseProxy = false;
            }

            return handler;
        }

        private SslClientAuthenticationOptions BuildHttp2SslOptions(
            string host,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings)
        {
            var sslProtocols = tlsSettings.EnabledProtocols ?? fingerprint.GetSslProtocols();
            var cipherSuites = fingerprint.GetCipherSuites();
            var configuredProtocols = tlsSettings.ApplicationProtocols ?? fingerprint.GetApplicationProtocols();

            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = sslProtocols,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                ClientCertificates = new System.Security.Cryptography.X509Certificates.X509CertificateCollection()
            };

            if (cipherSuites?.Length > 0)
            {
                try
                {
                    sslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(cipherSuites);
                }
                catch (PlatformNotSupportedException)
                {
                    // The current platform does not support configuring cipher suites.
                }
            }

            var protocols = new List<SslApplicationProtocol>();
            var hasHttp2 = false;
            var hasHttp11 = false;

            if (configuredProtocols != null)
            {
                foreach (var protocol in configuredProtocols)
                {
                    if (protocol.Equals("h2", StringComparison.OrdinalIgnoreCase))
                    {
                        hasHttp2 = true;
                    }

                    if (protocol.Equals("http/1.1", StringComparison.OrdinalIgnoreCase))
                    {
                        hasHttp11 = true;
                    }

                    protocols.Add(new SslApplicationProtocol(Encoding.ASCII.GetBytes(protocol)));
                }
            }

            if (!hasHttp2)
            {
                protocols.Insert(0, SslApplicationProtocol.Http2);
            }

            if (!hasHttp11)
            {
                protocols.Add(SslApplicationProtocol.Http11);
            }

            sslOptions.ApplicationProtocols = protocols;

            sslOptions.RemoteCertificateValidationCallback = tlsSettings.ValidateCertificate
                ? tlsSettings.CertificateValidationCallback ?? _options.CertificateValidationCallback
                : _options.CertificateValidationCallback;

            return sslOptions;
        }
    }
}
