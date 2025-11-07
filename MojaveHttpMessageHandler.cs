using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    internal sealed class MojaveHttpMessageHandler : HttpMessageHandler
    {
        private static readonly Lazy<PropertyInfo> s_connectTimeoutProperty = new(() =>
            typeof(SocketsHttpHandler).GetProperty("ConnectTimeout", BindingFlags.Public | BindingFlags.Instance));

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
                var fingerprint = GetEffectiveFingerprint(requestOptions);
                var tlsSettings = requestOptions?.TlsSettings ?? _options.TlsSettingsProvider?.Invoke() ?? MojaveTlsSettings.Default;
                var maxRetries = Math.Max(0, requestOptions?.MaxConnectionRetries ?? _options.MaxConnectionRetries);
                var retryDelay = requestOptions?.RetryDelay ?? _options.ConnectionRetryDelay;
                var forceCloseConnections = (requestOptions?.ForceCloseConnectionsAfterRequest ?? false) || _options.ForceCloseConnectionsAfterRequest;
                var socketBufferSize = requestOptions?.SocketBufferSize ?? _options.SocketBufferSize;
                var maxConnectionsPerHost = requestOptions?.MaxConnectionsPerHost ?? _options.MaxConnectionsPerHost;
                var affinityKey = forceCloseConnections ? null : requestOptions?.SessionAffinityKey ?? cookieManager;
                if (retryDelay < TimeSpan.Zero)
                {
                    retryDelay = TimeSpan.Zero;
                }

                if (forceCloseConnections && currentRequest.Headers.ConnectionClose != true)
                {
                    currentRequest.Headers.ConnectionClose = true;
                }

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

                var initialProxy = GetProxyForAttempt(requestOptions, 0);

                HttpResponseMessage response = ShouldUseHttp2(currentRequest, initialProxy)
                    ? await SendHttp2Async(currentRequest, uri, effectiveTimeout, fingerprint, tlsSettings, requestOptions, initialProxy, maxRetries, retryDelay, cancellationToken).ConfigureAwait(false)
                    : await SendHttp11Async(currentRequest, uri, useTls, effectiveTimeout, fingerprint, tlsSettings, requestOptions, cookieManager, affinityKey, socketBufferSize, maxConnectionsPerHost, initialProxy, maxRetries, retryDelay, forceCloseConnections, cancellationToken).ConfigureAwait(false);

                if (cookieManager != null && response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
                {
                    cookieManager.UpdateFromSetCookieHeaders(uri, setCookieHeaders);
                }

                var redirectOptions = currentRequest.GetMojaveOptions();
                var allowRedirect = redirectOptions?.AllowAutoRedirect ?? requestOptions?.AllowAutoRedirect ?? _options.AllowAutoRedirect;

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

        private JA3Fingerprint GetEffectiveFingerprint(MojaveRequestOptions requestOptions)
        {
            if (!_options.EnableJa3Fingerprinting)
            {
                return null;
            }

            if (requestOptions?.Fingerprint != null)
            {
                return requestOptions.Fingerprint;
            }

            return _options.FingerprintProvider?.Invoke() ?? JA3Fingerprint.Default;
        }

        private static MojaveProxyOptions GetProxyForAttempt(MojaveRequestOptions options, int attempt)
            => GetProxyForAttempt(options, attempt, options?.Proxy);

        private static MojaveProxyOptions GetProxyForAttempt(MojaveRequestOptions options, int attempt, MojaveProxyOptions initialProxy)
        {
            if (options == null)
            {
                return MojaveProxyOptions.NoProxy;
            }

            if (attempt == 0)
            {
                var proxy = initialProxy ?? options.Proxy;
                if (proxy != null)
                {
                    return proxy;
                }
            }

            var selector = options.ProxySelector;
            if (selector != null)
            {
                var resolved = selector(attempt);
                if (resolved != null)
                {
                    if (attempt == 0 && options.Proxy == null)
                    {
                        options.Proxy = resolved;
                    }

                    return resolved;
                }
            }

            return options.Proxy ?? MojaveProxyOptions.NoProxy;
        }

        private static bool IsRedirect(HttpStatusCode statusCode)
        {
            return statusCode == HttpStatusCode.Moved ||
                   statusCode == HttpStatusCode.Redirect ||
                   statusCode == HttpStatusCode.RedirectMethod ||
                   statusCode == HttpStatusCode.TemporaryRedirect ||
                   (int)statusCode == 308;
        }

        private static bool ShouldUseHttp2(HttpRequestMessage request, MojaveProxyOptions proxyOptions)
        {
            if (request?.Version == null)
            {
                return false;
            }

            if (request.Version.Major < 2)
            {
                return false;
            }

            var descriptor = proxyOptions?.Descriptor;
            if (descriptor == null)
            {
                return true;
            }

            return descriptor.Scheme is ProxyScheme.Http or ProxyScheme.Https;
        }

        private async Task<HttpResponseMessage> SendHttp11Async(
            HttpRequestMessage request,
            Uri uri,
            bool useTls,
            TimeSpan timeout,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            MojaveRequestOptions requestOptions,
            MojaveCookieManager cookieManager,
            object affinityKey,
            int socketBufferSize,
            int maxConnectionsPerHost,
            MojaveProxyOptions initialProxy,
            int maxRetries,
            TimeSpan retryDelay,
            bool forceCloseConnections,
            CancellationToken cancellationToken)
        {
            var requestWantsClose = RequestWantsConnectionClose(request);
            byte[] cachedRequestPayload = null;
            var requestPayloadDirty = true;
            var targetPort = uri.IsDefaultPort ? (useTls ? 443 : 80) : uri.Port;

            Exception lastException = null;

            for (int attempt = 0; attempt <= maxRetries; attempt++)
            {
                var proxyOptions = GetProxyForAttempt(requestOptions, attempt, initialProxy);
                TlsClientLease lease = null;
                CancellationTokenSource waitCts = null;
                CancellationTokenSource linkedCts = null;

                try
                {
                    var waitToken = cancellationToken;
                    if (timeout > TimeSpan.Zero)
                    {
                        waitCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        waitCts.CancelAfter(timeout);
                        waitToken = waitCts.Token;
                    }

                    lease = await TlsConnectionPool.Shared.RentAsync(
                        uri.Host,
                        targetPort,
                        useTls,
                        fingerprint,
                        tlsSettings,
                        proxyOptions?.Descriptor,
                        affinityKey,
                        _options.CertificateValidationCallback,
                        maxConnectionsPerHost,
                        socketBufferSize,
                        waitToken).ConfigureAwait(false);

                    linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    if (timeout > TimeSpan.Zero)
                    {
                        linkedCts.CancelAfter(timeout);
                    }

                    if (requestPayloadDirty || cachedRequestPayload == null)
                    {
                        cachedRequestPayload = await HttpRequestStringifier.Stringify(request).ConfigureAwait(false);
                        requestPayloadDirty = false;
                    }

                    var requestPayload = cachedRequestPayload;
                    var responseBytes = await lease.Client.SendRequestAsync(requestPayload, linkedCts.Token, useTls).ConfigureAwait(false);
                    var response = HttpResponseParser.Parse(responseBytes);
                    response.RequestMessage = request;

                    var shouldClose = requestWantsClose || ResponseIndicatesConnectionClose(response);
                    if (shouldClose)
                    {
                        lease.MarkUnusable();
                    }
                    else
                    {
                        lease.MarkReusable();
                    }

                    proxyOptions?.RotationListener?.OnSuccess(proxyOptions);
                    return response;
                }
                catch (OperationCanceledException) when (linkedCts != null && linkedCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    lease?.MarkUnusable();
                    var timeoutException = new TimeoutException("The HTTP/1.1 request timed out.");
                    proxyOptions?.RotationListener?.OnFailure(proxyOptions, timeoutException);
                    throw timeoutException;
                }
                catch (OperationCanceledException) when (waitCts != null && waitCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    lease?.MarkUnusable();
                    var timeoutException = new TimeoutException("The HTTP/1.1 connection attempt timed out.");
                    proxyOptions?.RotationListener?.OnFailure(proxyOptions, timeoutException);
                    throw timeoutException;
                }
                catch (Exception ex)
                {
                    lease?.MarkUnusable();

                    var exceptionToHandle = AugmentSocketResourceException(
                        ex,
                        uri,
                        targetPort,
                        useTls,
                        fingerprint,
                        tlsSettings,
                        proxyOptions,
                        cookieManager,
                        affinityKey,
                        socketBufferSize,
                        maxConnectionsPerHost,
                        forceCloseConnections);

                    forceCloseConnections = _options.ForceCloseConnectionsAfterRequest || forceCloseConnections;
                    if (forceCloseConnections)
                    {
                        affinityKey = null;
                    }

                    if (forceCloseConnections && request.Headers.ConnectionClose != true)
                    {
                        request.Headers.ConnectionClose = true;
                        requestWantsClose = true;
                        requestPayloadDirty = true;
                    }

                    if (TlsPlatformSupport.TryDisableCipherSuitesPolicy(exceptionToHandle))
                    {
                        lastException = exceptionToHandle;
                        attempt--;
                        continue;
                    }

                    var transformed = NormalizeProxyException(exceptionToHandle, proxyOptions);

                    if (attempt < maxRetries && ShouldRetry(transformed, proxyOptions))
                    {
                        lastException = transformed;
                        proxyOptions?.RotationListener?.OnFailure(proxyOptions, transformed);
                        await DelayForRetryAsync(attempt, retryDelay, transformed, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    lastException = transformed;
                    proxyOptions?.RotationListener?.OnFailure(proxyOptions, transformed);
                    throw transformed;
                }
                finally
                {
                    linkedCts?.Dispose();
                    waitCts?.Dispose();
                    lease?.Dispose();
                }
            }

            throw lastException ?? new HttpRequestException("The HTTP/1.1 request failed after retrying the connection.");
        }

        private async Task<HttpResponseMessage> SendHttp2Async(
            HttpRequestMessage request,
            Uri uri,
            TimeSpan timeout,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            MojaveRequestOptions requestOptions,
            MojaveProxyOptions initialProxy,
            int maxRetries,
            TimeSpan retryDelay,
            CancellationToken cancellationToken)
        {
            Exception lastException = null;

            for (int attempt = 0; attempt <= maxRetries; attempt++)
            {
                var proxyOptions = GetProxyForAttempt(requestOptions, attempt, initialProxy);
                using var handler = CreateHttp2Handler(uri, fingerprint, tlsSettings, proxyOptions);
                ApplyHttp2ConnectTimeout(handler, timeout);

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
                        proxyOptions?.RotationListener?.OnSuccess(proxyOptions);
                        return finalResponse;
                    }
                }
                catch (OperationCanceledException) when (linkedCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    var timeoutException = new TimeoutException("The HTTP/2 request timed out.");
                    proxyOptions?.RotationListener?.OnFailure(proxyOptions, timeoutException);
                    throw timeoutException;
                }
                catch (AuthenticationException ex)
                {
                    if (TlsPlatformSupport.TryDisableCipherSuitesPolicy(ex))
                    {
                        lastException = ex;
                        attempt--;
                        continue;
                    }

                    if (proxyOptions?.Descriptor == null)
                    {
                        lastException = ex;
                        proxyOptions?.RotationListener?.OnFailure(proxyOptions, ex);
                        throw;
                    }

                    var proxyException = new ProxyException(
                        "Failed to establish a secure connection through the proxy.",
                        ProxyErrorReason.ConnectionFailed,
                        innerException: ex);

                    if (attempt < maxRetries && IsRetryableProxyError(proxyException))
                    {
                        lastException = proxyException;
                        proxyOptions?.RotationListener?.OnFailure(proxyOptions, proxyException);
                        await DelayForRetryAsync(attempt, retryDelay, proxyException, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    proxyOptions?.RotationListener?.OnFailure(proxyOptions, proxyException);
                    throw proxyException;
                }
                catch (HttpRequestException ex)
                {
                    if (TlsPlatformSupport.TryDisableCipherSuitesPolicy(ex))
                    {
                        lastException = ex;
                        attempt--;
                        continue;
                    }

                    var transformed = NormalizeProxyException(ex, proxyOptions);
                    lastException = transformed;

                    if (transformed is ProxyException proxyException)
                    {
                        if (attempt < maxRetries && IsRetryableProxyError(proxyException))
                        {
                            proxyOptions?.RotationListener?.OnFailure(proxyOptions, proxyException);
                            await DelayForRetryAsync(attempt, retryDelay, proxyException, cancellationToken).ConfigureAwait(false);
                            continue;
                        }

                        proxyOptions?.RotationListener?.OnFailure(proxyOptions, proxyException);
                        throw proxyException;
                    }

                    if (attempt < maxRetries && ShouldRetry(transformed, proxyOptions))
                    {
                        proxyOptions?.RotationListener?.OnFailure(proxyOptions, transformed);
                        await DelayForRetryAsync(attempt, retryDelay, transformed, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    proxyOptions?.RotationListener?.OnFailure(proxyOptions, transformed);
                    throw transformed;
                }
                catch (Exception ex)
                {
                    if (TlsPlatformSupport.TryDisableCipherSuitesPolicy(ex))
                    {
                        lastException = ex;
                        attempt--;
                        continue;
                    }

                    var transformed = NormalizeProxyException(ex, proxyOptions);

                    if (attempt < maxRetries && ShouldRetry(transformed, proxyOptions))
                    {
                        lastException = transformed;
                        proxyOptions?.RotationListener?.OnFailure(proxyOptions, transformed);
                        await DelayForRetryAsync(attempt, retryDelay, transformed, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    lastException = transformed;
                    proxyOptions?.RotationListener?.OnFailure(proxyOptions, transformed);
                    throw transformed;
                }
            }

            throw lastException ?? new HttpRequestException("The HTTP/2 request failed after retrying the connection.");
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

        private SocketsHttpHandler CreateHttp2Handler(
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
                EnableMultipleHttp2Connections = true,
                MaxConnectionsPerServer = Math.Max(_options.MaxConnectionsPerHost, 1)
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
                                _options.CertificateValidationCallback,
                                _options.SocketBufferSize);

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

        private static void ApplyHttp2ConnectTimeout(SocketsHttpHandler handler, TimeSpan timeout)
        {
            if (handler == null || timeout <= TimeSpan.Zero)
            {
                return;
            }

            if (TrySetConnectTimeout(handler, timeout))
            {
                return;
            }

            if (handler.ConnectCallback != null)
            {
                return;
            }

            handler.ConnectCallback = async (context, token) =>
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(timeout);

                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };

                try
                {
                    await socket.ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port).WaitAsync(cts.Token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
                finally
                {
                    cts.Dispose();
                }
            };
        }

        private static bool TrySetConnectTimeout(SocketsHttpHandler handler, TimeSpan timeout)
        {
            var property = s_connectTimeoutProperty.Value;
            if (property == null || !property.CanWrite)
            {
                return false;
            }

            try
            {
                property.SetValue(handler, timeout);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool ShouldRetry(Exception exception, MojaveProxyOptions proxyOptions)
        {
            if (exception is OperationCanceledException or TimeoutException)
            {
                return false;
            }

            if (exception is ProxyException proxyException)
            {
                return IsRetryableProxyError(proxyException);
            }

            if (exception is AuthenticationException)
            {
                return true;
            }

            if (exception is IOException or SocketException)
            {
                return true;
            }

            if (exception is HttpRequestException httpRequestException)
            {
                if (httpRequestException.StatusCode.HasValue)
                {
                    return false;
                }

                return httpRequestException.InnerException != null
                    ? ShouldRetry(httpRequestException.InnerException, proxyOptions)
                    : true;
            }

            return exception.InnerException != null && ShouldRetry(exception.InnerException, proxyOptions);
        }

        private static bool RequestWantsConnectionClose(HttpRequestMessage request)
        {
            if (request == null)
            {
                return false;
            }

            if (request.Headers.ConnectionClose == true)
            {
                return true;
            }

            foreach (var value in request.Headers.Connection)
            {
                if (string.Equals(value, "close", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool ResponseIndicatesConnectionClose(HttpResponseMessage response)
        {
            if (response == null)
            {
                return true;
            }

            if (response.Headers.ConnectionClose == true)
            {
                return true;
            }

            foreach (var value in response.Headers.Connection)
            {
                if (string.Equals(value, "close", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            if (response.Version != null && response.Version.Major == 1 && response.Version.Minor == 0)
            {
                return true;
            }

            return false;
        }

        private static bool IsRetryableProxyError(ProxyException proxyException)
        {
            return proxyException != null && proxyException.Reason is ProxyErrorReason.ConnectionFailed or ProxyErrorReason.ProtocolError;
        }

        private static Exception NormalizeProxyException(Exception exception, MojaveProxyOptions proxyOptions)
        {
            if (exception == null || proxyOptions?.Descriptor == null || exception is ProxyException)
            {
                return exception;
            }

            switch (exception)
            {
                case HttpRequestException httpRequestException:
                    return CreateProxyException(httpRequestException);
                case AuthenticationException authenticationException:
                    return new ProxyException(
                        "Failed to establish a secure connection through the proxy.",
                        ProxyErrorReason.ConnectionFailed,
                        innerException: authenticationException);
                case TimeoutException timeoutException:
                    return new ProxyException(
                        "The proxy did not respond within the allotted timeout.",
                        ProxyErrorReason.ConnectionFailed,
                        innerException: timeoutException);
                case SocketException or IOException:
                    return new ProxyException(
                        "Failed to communicate with the proxy server.",
                        ProxyErrorReason.ConnectionFailed,
                        innerException: exception);
                case WebException webException:
                    {
                        var statusCode = (webException.Response as HttpWebResponse)?.StatusCode;
                        var reason = webException.Status == WebExceptionStatus.ProtocolError
                            ? ProxyErrorReason.ProtocolError
                            : ProxyErrorReason.ConnectionFailed;

                        return new ProxyException(
                            webException.Message,
                            reason,
                            statusCode,
                            webException);
                    }
                default:
                    return exception;
            }
        }

        private static async Task DelayForRetryAsync(
            int attempt,
            TimeSpan baseDelay,
            Exception exception,
            CancellationToken cancellationToken)
        {
            var effectiveDelay = CalculateDelay(baseDelay, attempt, exception);
            if (effectiveDelay > TimeSpan.Zero)
            {
                await Task.Delay(effectiveDelay, cancellationToken).ConfigureAwait(false);
            }
        }

        private static TimeSpan CalculateDelay(TimeSpan baseDelay, int attempt, Exception exception)
        {
            var socketException = FindSocketException(exception);
            if (socketException?.SocketErrorCode == SocketError.AccessDenied)
            {
                return TimeSpan.FromSeconds(3);
            }

            if (baseDelay <= TimeSpan.Zero)
            {
                return TimeSpan.Zero;
            }

            var multiplier = Math.Pow(2, Math.Max(0, attempt));
            var delayMilliseconds = baseDelay.TotalMilliseconds * multiplier;
            var cappedMilliseconds = Math.Min(delayMilliseconds, 2000);
            return TimeSpan.FromMilliseconds(cappedMilliseconds);
        }

        private Exception AugmentSocketResourceException(
            Exception exception,
            Uri uri,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            MojaveProxyOptions proxyOptions,
            MojaveCookieManager cookieManager,
            object affinityKey,
            int socketBufferSize,
            int maxConnectionsPerHost,
            bool forceCloseConnections)
        {
            var socketException = FindSocketException(exception);
            if (socketException == null)
            {
                return exception;
            }

            switch (socketException.SocketErrorCode)
            {
                case SocketError.NoBufferSpaceAvailable:
                    var noBufferSpaceException = CreateSocketResourceException(
                        socketException,
                        uri,
                        port,
                        useTls,
                        fingerprint,
                        tlsSettings,
                        proxyOptions,
                        cookieManager,
                        affinityKey,
                        forceCloseConnections,
                        "The operating system ran out of socket buffer space while communicating with ",
                        "Reduce concurrent connections or lower MojaveHttpClientOptions.SocketBufferSize to avoid exhausting kernel buffers.",
                        socketBufferSize);
                    var socketBufferReduced = _options.TryReduceSocketBufferSize(socketBufferSize);
                    var maxConnectionsReduced = _options.TryReduceMaxConnectionsPerHost(maxConnectionsPerHost);
                    var forceCloseActivated = _options.TryEnableForceCloseConnections();
                    if (forceCloseActivated)
                    {
                        forceCloseConnections = true;
                        affinityKey = null;
                        if (uri != null)
                        {
                            TlsConnectionPool.Shared.ClearHostVariants(uri.Host, port, useTls);
                        }
                    }
                    if (maxConnectionsReduced)
                    {
                        ReducePoolMaxConnections(
                            uri,
                            port,
                            useTls,
                            fingerprint,
                            tlsSettings,
                            proxyOptions,
                            affinityKey,
                            socketBufferSize,
                            socketBufferReduced,
                            forceCloseConnections);
                    }
                    return noBufferSpaceException;
                case SocketError.AddressAlreadyInUse:
                    var addressInUseException = CreateSocketResourceException(
                        socketException,
                        uri,
                        port,
                        useTls,
                        fingerprint,
                        tlsSettings,
                        proxyOptions,
                        cookieManager,
                        affinityKey,
                        forceCloseConnections,
                        "The operating system refused to open a new socket because the local port range is exhausted while communicating with ",
                        "Reduce concurrent connections or lower MojaveHttpClientOptions.MaxConnectionsPerHost to avoid running out of ephemeral ports.",
                        socketBufferSize);
                    var forceCloseEnabled = _options.TryEnableForceCloseConnections();
                    if (forceCloseEnabled)
                    {
                        forceCloseConnections = true;
                        affinityKey = null;
                        if (uri != null)
                        {
                            TlsConnectionPool.Shared.ClearHostVariants(uri.Host, port, useTls);
                        }
                    }
                    if (_options.TryReduceMaxConnectionsPerHost(maxConnectionsPerHost))
                    {
                        ReducePoolMaxConnections(
                            uri,
                            port,
                            useTls,
                            fingerprint,
                            tlsSettings,
                            proxyOptions,
                            affinityKey,
                            socketBufferSize,
                            socketBufferReduced: false,
                            forceCloseConnections);
                    }
                    return addressInUseException;
                default:
                    return exception;
            }
        }
        private HttpRequestException CreateSocketResourceException(
            SocketException socketException,
            Uri uri,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            MojaveProxyOptions proxyOptions,
            MojaveCookieManager cookieManager,
            object affinityKey,
            bool forceCloseConnections,
            string prefixMessage,
            string mitigationMessage,
            int socketBufferSize)
        {
            var effectiveAffinity = forceCloseConnections ? null : affinityKey;

            TlsConnectionPool.Shared.Clear(
                uri?.Host,
                port,
                useTls,
                fingerprint,
                tlsSettings,
                proxyOptions?.Descriptor,
                effectiveAffinity,
                socketBufferSize);

            var messageBuilder = new StringBuilder();
            messageBuilder.Append(prefixMessage);
            messageBuilder.Append(uri?.Host ?? "the remote host");
            messageBuilder.Append('.');
            messageBuilder.Append(' ');
            messageBuilder.Append(mitigationMessage);

            return new HttpRequestException(messageBuilder.ToString(), socketException);
        }
        private void ReducePoolMaxConnections(
            Uri uri,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            MojaveProxyOptions proxyOptions,
            object affinityKey,
            int observedSocketBufferSize,
            bool socketBufferReduced,
            bool forceCloseConnections)
        {
            if (uri == null)
            {
                return;
            }

            var descriptor = proxyOptions?.Descriptor;
            var effectiveAffinity = forceCloseConnections ? null : affinityKey;
            var maxConnections = _options.MaxConnectionsPerHost;

            TlsConnectionPool.Shared.AdjustMaxConnections(
                uri.Host,
                port,
                useTls,
                fingerprint,
                tlsSettings,
                descriptor,
                effectiveAffinity,
                observedSocketBufferSize,
                maxConnections);

            if (!socketBufferReduced)
            {
                return;
            }

            var newSocketBufferSize = _options.SocketBufferSize;
            if (newSocketBufferSize == observedSocketBufferSize)
            {
                return;
            }

            TlsConnectionPool.Shared.AdjustMaxConnections(
                uri.Host,
                port,
                useTls,
                fingerprint,
                tlsSettings,
                descriptor,
                effectiveAffinity,
                newSocketBufferSize,
                maxConnections);
        }

        private static SocketException FindSocketException(Exception exception)
        {
            var current = exception;
            while (current != null)
            {
                if (current is SocketException socketException)
                {
                    return socketException;
                }

                current = current.InnerException;
            }

            return null;
        }

        private SslClientAuthenticationOptions BuildHttp2SslOptions(
            string host,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings)
        {
            var sslProtocols = tlsSettings.EnabledProtocols ?? fingerprint?.GetSslProtocols() ?? SslProtocols.None;
            var cipherSuites = fingerprint?.GetCipherSuites();
            var configuredProtocols = tlsSettings.ApplicationProtocols ?? fingerprint?.GetApplicationProtocols();

            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = sslProtocols,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                ClientCertificates = new System.Security.Cryptography.X509Certificates.X509CertificateCollection()
            };

            if (cipherSuites?.Length > 0 && TlsPlatformSupport.SupportsCipherSuitesPolicy())
            {
                try
                {
                    sslOptions.CipherSuitesPolicy = new CipherSuitesPolicy(cipherSuites);
                }
                catch (PlatformNotSupportedException)
                {
                    // Some environments may still reject custom cipher suites despite the capability check.
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

            if (protocols.Count == 0)
            {
                protocols.Add(SslApplicationProtocol.Http2);
                protocols.Add(SslApplicationProtocol.Http11);
                hasHttp2 = true;
                hasHttp11 = true;
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

        private static ProxyException CreateProxyException(HttpRequestException exception)
        {
            var statusCode = exception.StatusCode ?? ExtractStatusCodeFromMessage(exception.Message);

            if (statusCode == HttpStatusCode.ProxyAuthenticationRequired)
            {
                return new ProxyException(
                    "Proxy authentication required. Provide valid proxy credentials.",
                    ProxyErrorReason.AuthenticationRequired,
                    statusCode,
                    exception);
            }

            if (statusCode == HttpStatusCode.Forbidden || statusCode == HttpStatusCode.Unauthorized)
            {
                return new ProxyException(
                    "Proxy authentication failed. Verify the configured proxy username and password.",
                    ProxyErrorReason.AuthenticationFailed,
                    statusCode,
                    exception);
            }

            if (exception.InnerException is AuthenticationException)
            {
                return new ProxyException(
                    "Failed to establish a secure connection through the proxy.",
                    ProxyErrorReason.ConnectionFailed,
                    statusCode,
                    exception);
            }

            var message = statusCode != null
                ? $"Proxy request failed with status code {(int)statusCode} ({statusCode})."
                : "Proxy request failed.";

            return new ProxyException(message, ProxyErrorReason.ResponseError, statusCode, exception);
        }

        private static HttpStatusCode? ExtractStatusCodeFromMessage(string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return null;
            }

            const string marker = "status code '";
            var index = message.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return null;
            }

            var start = index + marker.Length;
            var end = message.IndexOf('\'', start);
            if (end <= start)
            {
                return null;
            }

            if (!int.TryParse(message.Substring(start, end - start), out var numericCode))
            {
                return null;
            }

            if (!Enum.IsDefined(typeof(HttpStatusCode), numericCode))
            {
                return null;
            }

            return (HttpStatusCode)numericCode;
        }
    }
}
