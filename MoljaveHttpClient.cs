using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    public sealed class MojaveHttpClient : IDisposable
    {
        private static readonly Version s_defaultRequestVersion = HttpVersion.Version11;

        private readonly MojaveHttpClientOptions _options;
        private readonly HttpMessageInvoker _invoker;
        private readonly MojaveCookieManager _cookieManager;
        private readonly object _fingerprintLock = new();
        private readonly object _proxyLock = new();
        private readonly HttpRequestMessage _defaultRequest = new();
        private readonly HttpRequestHeaders _defaultRequestHeaders;

        private Func<JA3Fingerprint> _fingerprintFactory;
        private JA3Fingerprint _currentFingerprint;

        private readonly bool _ja3FingerprintingEnabled;

        private Func<MojaveProxyOptions> _defaultProxyResolver;
        private Func<MojaveProxyOptions> _overrideProxyResolver;
        private MojaveProxyOptions _staticProxyOptions;
        private bool _proxyEnabled = true;

        private Uri _baseAddress;
        private Version _defaultRequestVersion = s_defaultRequestVersion;
        private int _defaultVersionPolicy = (int)HttpVersionPolicy.RequestVersionOrHigher;
        private long _maxResponseContentBufferSize = int.MaxValue;
        private bool _disposed;

        public MojaveHttpClient()
            : this(new MojaveHttpClientOptions())
        {
        }

        public MojaveHttpClient(CookieContainer cookieContainer, WebProxy proxy = null)
            : this(options =>
            {
                if (cookieContainer != null)
                {
                    options.CookieContainer = cookieContainer;
                }

                if (proxy != null)
                {
                    options.ProxyResolver = () => MojaveProxyOptions.FromWebProxy(proxy);
                }
            })
        {
            if (proxy != null)
            {
                SetProxy(proxy);
            }
        }

        public MojaveHttpClient(Action<MojaveHttpClientOptions> configure)
            : this(BuildOptions(configure))
        {
        }

        public MojaveHttpClient(MojaveHttpClientOptions options)
        {
            PlatformRequirements.EnsureSupportedWindows();

            _options = options ?? throw new ArgumentNullException(nameof(options));
            _ja3FingerprintingEnabled = _options.EnableJa3Fingerprinting &&
                _options.FingerprintPreset != Ja3Preset.Disabled;

            _cookieManager = _options.CookieManager ?? new MojaveCookieManager();
            _options.CookieManager = _cookieManager;

            _defaultRequestHeaders = _defaultRequest.Headers;

            if (_ja3FingerprintingEnabled)
            {
                InitializeFingerprint(_options.FingerprintProvider);
                _options.FingerprintProvider = ResolveFingerprint;
            }
            else
            {
                _fingerprintFactory = null;
                _currentFingerprint = null;
                _options.FingerprintProvider = null;
            }

            InitializeProxy(_options.ProxyResolver);
            _options.ProxyResolver = ResolveProxy;

            _invoker = new HttpMessageInvoker(_options.BuildHandlerPipeline(), disposeHandler: true);
        }

        public Uri BaseAddress
        {
            get => Volatile.Read(ref _baseAddress);
            set
            {
                if (value != null && !value.IsAbsoluteUri)
                {
                    throw new ArgumentException("BaseAddress must be an absolute URI.", nameof(value));
                }

                Volatile.Write(ref _baseAddress, value);
            }
        }

        public HttpRequestHeaders DefaultRequestHeaders => _defaultRequestHeaders;

        public Version DefaultRequestVersion
        {
            get => Volatile.Read(ref _defaultRequestVersion);
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                Volatile.Write(ref _defaultRequestVersion, value);
            }
        }

        public HttpVersionPolicy DefaultVersionPolicy
        {
            get => (HttpVersionPolicy)Volatile.Read(ref _defaultVersionPolicy);
            set => Volatile.Write(ref _defaultVersionPolicy, (int)value);
        }

        public long MaxResponseContentBufferSize
        {
            get => Volatile.Read(ref _maxResponseContentBufferSize);
            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), value, "The buffer size cannot be negative.");
                }

                Volatile.Write(ref _maxResponseContentBufferSize, value);
            }
        }

        public TimeSpan Timeout
        {
            get => _options.DefaultTimeout;
            set => _options.DefaultTimeout = value;
        }

        public bool AllowAutoRedirect
        {
            get => _options.AllowAutoRedirect;
            set => _options.AllowAutoRedirect = value;
        }

        public int MaxAutomaticRedirections
        {
            get => _options.MaxAutomaticRedirections;
            set => _options.MaxAutomaticRedirections = value;
        }

        public bool ForceCloseConnectionsAfterRequest
        {
            get => _options.ForceCloseConnectionsAfterRequest;
            set => _options.ForceCloseConnectionsAfterRequest = value;
        }

        public int MaxConnectionRetries
        {
            get => _options.MaxConnectionRetries;
            set => _options.MaxConnectionRetries = value;
        }

        public TimeSpan ConnectionRetryDelay
        {
            get => _options.ConnectionRetryDelay;
            set => _options.ConnectionRetryDelay = value;
        }

        public int MaxConnectionsPerHost
        {
            get => _options.MaxConnectionsPerHost;
            set => _options.MaxConnectionsPerHost = value;
        }

        public CookieContainer CookieContainer
        {
            get => _cookieManager.GetInternalContainer();
            set => _cookieManager.ReplaceWith(value ?? new CookieContainer());
        }

        public MojaveCookieManager CookieManager => _cookieManager;

        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
            => SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);

        public async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            HttpCompletionOption completionOption,
            CancellationToken cancellationToken = default)
        {
            if (completionOption is not HttpCompletionOption.ResponseContentRead and not HttpCompletionOption.ResponseHeadersRead)
            {
                throw new ArgumentOutOfRangeException(nameof(completionOption));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(MojaveHttpClient));
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            PrepareRequest(request);
            ApplyDefaultRequestOptions(request);

            HttpResponseMessage response = await _invoker.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (completionOption == HttpCompletionOption.ResponseContentRead)
            {
                await EnsureContentBufferedAsync(response, cancellationToken).ConfigureAwait(false);
            }

            return response;
        }

        public Task<HttpResponseMessage> GetAsync(string requestUri)
            => GetAsync(CreateUri(requestUri), HttpCompletionOption.ResponseContentRead, CancellationToken.None);

        public Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption completionOption)
            => GetAsync(CreateUri(requestUri), completionOption, CancellationToken.None);

        public Task<HttpResponseMessage> GetAsync(string requestUri, CancellationToken cancellationToken)
            => GetAsync(CreateUri(requestUri), HttpCompletionOption.ResponseContentRead, cancellationToken);

        public Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken)
            => GetAsync(CreateUri(requestUri), completionOption, cancellationToken);

        public Task<HttpResponseMessage> GetAsync(Uri requestUri)
            => GetAsync(requestUri, HttpCompletionOption.ResponseContentRead, CancellationToken.None);

        public Task<HttpResponseMessage> GetAsync(Uri requestUri, HttpCompletionOption completionOption)
            => GetAsync(requestUri, completionOption, CancellationToken.None);

        public async Task<HttpResponseMessage> GetAsync(Uri requestUri, CancellationToken cancellationToken)
            => await GetAsync(requestUri, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);

        public async Task<HttpResponseMessage> GetAsync(Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken)
        {
            using var request = CreateRequestMessage(HttpMethod.Get, requestUri);
            return await SendAsync(request, completionOption, cancellationToken).ConfigureAwait(false);
        }

        public async Task<string> GetStringAsync(string requestUri)
            => await GetStringAsync(CreateUri(requestUri), CancellationToken.None).ConfigureAwait(false);

        public async Task<string> GetStringAsync(string requestUri, CancellationToken cancellationToken)
            => await GetStringAsync(CreateUri(requestUri), cancellationToken).ConfigureAwait(false);

        public async Task<string> GetStringAsync(Uri requestUri)
            => await GetStringAsync(requestUri, CancellationToken.None).ConfigureAwait(false);

        public async Task<string> GetStringAsync(Uri requestUri, CancellationToken cancellationToken)
        {
            using var response = await GetAsync(requestUri, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }

        public async Task<byte[]> GetByteArrayAsync(string requestUri)
            => await GetByteArrayAsync(CreateUri(requestUri), CancellationToken.None).ConfigureAwait(false);

        public async Task<byte[]> GetByteArrayAsync(string requestUri, CancellationToken cancellationToken)
            => await GetByteArrayAsync(CreateUri(requestUri), cancellationToken).ConfigureAwait(false);

        public async Task<byte[]> GetByteArrayAsync(string requestUri, bool bypassProxy, CancellationToken cancellationToken = default)
            => await GetByteArrayAsync(CreateUri(requestUri), bypassProxy, cancellationToken).ConfigureAwait(false);

        public async Task<byte[]> GetByteArrayAsync(Uri requestUri)
            => await GetByteArrayAsync(requestUri, CancellationToken.None).ConfigureAwait(false);

        public async Task<byte[]> GetByteArrayAsync(Uri requestUri, CancellationToken cancellationToken)
        {
            using var response = await GetAsync(requestUri, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }

        public async Task<byte[]> GetByteArrayAsync(Uri requestUri, bool bypassProxy, CancellationToken cancellationToken = default)
        {
            using var request = CreateRequestMessage(HttpMethod.Get, requestUri);
            if (bypassProxy)
            {
                request.ConfigureMojaveOptions(options =>
                {
                    options.Proxy = MojaveProxyOptions.NoProxy;
                });
            }

            using var response = await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }

        public async Task<Stream> GetStreamAsync(string requestUri)
            => await GetStreamAsync(CreateUri(requestUri), CancellationToken.None).ConfigureAwait(false);

        public async Task<Stream> GetStreamAsync(string requestUri, CancellationToken cancellationToken)
            => await GetStreamAsync(CreateUri(requestUri), cancellationToken).ConfigureAwait(false);

        public async Task<Stream> GetStreamAsync(Uri requestUri)
            => await GetStreamAsync(requestUri, CancellationToken.None).ConfigureAwait(false);

        public async Task<Stream> GetStreamAsync(Uri requestUri, CancellationToken cancellationToken)
        {
            var response = await GetAsync(requestUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            try
            {
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                response.Dispose();
                throw;
            }
        }

        public Task<HttpResponseMessage> PostAsync(string requestUri, HttpContent content)
            => PostAsync(CreateUri(requestUri), content, CancellationToken.None);

        public Task<HttpResponseMessage> PostAsync(string requestUri, HttpContent content, CancellationToken cancellationToken)
            => PostAsync(CreateUri(requestUri), content, cancellationToken);

        public Task<HttpResponseMessage> PostAsync(Uri requestUri, HttpContent content)
            => PostAsync(requestUri, content, CancellationToken.None);

        public async Task<HttpResponseMessage> PostAsync(Uri requestUri, HttpContent content, CancellationToken cancellationToken)
        {
            using var request = CreateRequestMessage(HttpMethod.Post, requestUri);
            request.Content = content;
            return await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
        }

        public Task<HttpResponseMessage> PutAsync(string requestUri, HttpContent content)
            => PutAsync(CreateUri(requestUri), content, CancellationToken.None);

        public Task<HttpResponseMessage> PutAsync(string requestUri, HttpContent content, CancellationToken cancellationToken)
            => PutAsync(CreateUri(requestUri), content, cancellationToken);

        public Task<HttpResponseMessage> PutAsync(Uri requestUri, HttpContent content)
            => PutAsync(requestUri, content, CancellationToken.None);

        public async Task<HttpResponseMessage> PutAsync(Uri requestUri, HttpContent content, CancellationToken cancellationToken)
        {
            using var request = CreateRequestMessage(HttpMethod.Put, requestUri);
            request.Content = content;
            return await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
        }

        public Task<HttpResponseMessage> DeleteAsync(string requestUri)
            => DeleteAsync(CreateUri(requestUri), CancellationToken.None);

        public Task<HttpResponseMessage> DeleteAsync(string requestUri, CancellationToken cancellationToken)
            => DeleteAsync(CreateUri(requestUri), cancellationToken);

        public Task<HttpResponseMessage> DeleteAsync(Uri requestUri)
            => DeleteAsync(requestUri, CancellationToken.None);

        public async Task<HttpResponseMessage> DeleteAsync(Uri requestUri, CancellationToken cancellationToken)
        {
            using var request = CreateRequestMessage(HttpMethod.Delete, requestUri);
            return await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
        }

        public void RotateFingerprint()
        {
            EnsureJa3FingerprintingEnabled();

            lock (_fingerprintLock)
            {
                _currentFingerprint = (_fingerprintFactory ?? ResolvePresetFactory())();
            }
        }

        public void UseFingerprintProvider(Func<JA3Fingerprint> provider, bool rotateImmediately = true)
        {
            EnsureJa3FingerprintingEnabled();

            if (provider == null)
            {
                throw new ArgumentNullException(nameof(provider));
            }

            lock (_fingerprintLock)
            {
                _fingerprintFactory = provider;
                _currentFingerprint = rotateImmediately ? provider() : null;
            }
        }

        public void SetProxy(WebProxy proxy)
        {
            lock (_proxyLock)
            {
                if (proxy == null)
                {
                    ClearConfiguredProxy();
                    _proxyEnabled = false;
                    return;
                }

                var options = MojaveProxyOptions.FromWebProxy(proxy);
                if (!options.HasProxy)
                {
                    ClearConfiguredProxy();
                    _overrideProxyResolver = null;
                    _proxyEnabled = false;
                    return;
                }

                _staticProxyOptions = options;
                _overrideProxyResolver = null;
                _proxyEnabled = true;
            }
        }

        public void ChangeProxy(WebProxy proxy)
        {
            lock (_proxyLock)
            {
                if (proxy == null)
                {
                    ClearConfiguredProxy();
                    return;
                }

                var options = MojaveProxyOptions.FromWebProxy(proxy);
                if (!options.HasProxy)
                {
                    ClearConfiguredProxy();
                    _overrideProxyResolver = null;
                    _proxyEnabled = false;
                    return;
                }

                _staticProxyOptions = options;
                _overrideProxyResolver = null;
            }
        }

        public void DisableProxy()
        {
            lock (_proxyLock)
            {
                _proxyEnabled = false;
            }
        }

        public void EnableProxy()
        {
            lock (_proxyLock)
            {
                _proxyEnabled = true;
            }
        }

        public Task<HttpResponseMessage> SendWithoutProxyAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
            => SendWithoutProxyAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);

        public Task<HttpResponseMessage> SendWithoutProxyAsync(
            HttpRequestMessage request,
            HttpCompletionOption completionOption,
            CancellationToken cancellationToken = default)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            request.ConfigureMojaveOptions(options =>
            {
                options.Proxy = MojaveProxyOptions.NoProxy;
            });

            return SendAsync(request, completionOption, cancellationToken);
        }

        public void SetProxyResolver(Func<MojaveProxyOptions> resolver)
        {
            lock (_proxyLock)
            {
                _overrideProxyResolver = resolver;
                ClearConfiguredProxy();
                if (resolver != null)
                {
                    _proxyEnabled = true;
                }
            }
        }

        public void SetProxyOptions(MojaveProxyOptions proxyOptions)
        {
            if (proxyOptions == null)
            {
                throw new ArgumentNullException(nameof(proxyOptions));
            }

            lock (_proxyLock)
            {
                ClearConfiguredProxy();
                _overrideProxyResolver = null;
                if (!proxyOptions.HasProxy)
                {
                    _proxyEnabled = false;
                    return;
                }

                _staticProxyOptions = proxyOptions;
                _proxyEnabled = true;
            }
        }

        public void ClearAllCookies() => _cookieManager.ClearAll();

        public void ClearCookiesForDomain(string domain) => _cookieManager.ClearDomain(domain);

        public void ClearCookiesForDomain(Uri uri) => _cookieManager.ClearDomain(uri);

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            var affinityKey = _options?.ForceCloseConnectionsAfterRequest == true
                ? null
                : _options?.CookieManager;
            TlsConnectionPool.Shared.ClearAffinity(affinityKey, includeNullAffinity: true);
            _invoker.Dispose();
            _defaultRequest.Dispose();
        }

        private void PrepareRequest(HttpRequestMessage request)
        {
            if (request.RequestUri == null)
            {
                var baseAddress = BaseAddress;
                if (baseAddress == null)
                {
                    throw new InvalidOperationException("The request URI must be absolute or BaseAddress must be set.");
                }

                request.RequestUri = baseAddress;
            }
            else if (!request.RequestUri.IsAbsoluteUri)
            {
                var baseAddress = BaseAddress;
                if (baseAddress == null)
                {
                    throw new InvalidOperationException("The request URI must be absolute or BaseAddress must be set.");
                }

                request.RequestUri = new Uri(baseAddress, request.RequestUri);
            }

            if (request.Version == null || request.Version == s_defaultRequestVersion)
            {
                request.Version = DefaultRequestVersion;
            }

            if (request.VersionPolicy == HttpVersionPolicy.RequestVersionOrLower)
            {
                request.VersionPolicy = DefaultVersionPolicy;
            }

            ApplyDefaultHeaders(request);
        }

        private void ApplyDefaultHeaders(HttpRequestMessage request)
        {
            if (_defaultRequestHeaders == null)
            {
                return;
            }

            foreach (var header in _defaultRequestHeaders)
            {
                if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value))
                {
                    request.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }
        }

        private void ApplyDefaultRequestOptions(HttpRequestMessage request)
        {
            request.ConfigureMojaveOptions(options =>
            {
                options.Timeout ??= _options.DefaultTimeout;
                options.AllowAutoRedirect ??= _options.AllowAutoRedirect;
                options.MaxAutomaticRedirections ??= _options.MaxAutomaticRedirections;
                options.CookieManager ??= _options.CookieManager;
                options.MaxConnectionRetries ??= _options.MaxConnectionRetries;
                options.RetryDelay ??= _options.ConnectionRetryDelay;
            });
        }

        private async Task EnsureContentBufferedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            if (response?.Content == null)
            {
                return;
            }

            cancellationToken.ThrowIfCancellationRequested();

            var maxBufferSize = Volatile.Read(ref _maxResponseContentBufferSize);
            if (maxBufferSize <= 0)
            {
                await response.Content.LoadIntoBufferAsync().ConfigureAwait(false);
            }
            else
            {
                await response.Content.LoadIntoBufferAsync(maxBufferSize).ConfigureAwait(false);
            }
        }

        private static Uri CreateUri(string requestUri)
        {
            if (requestUri == null)
            {
                throw new ArgumentNullException(nameof(requestUri));
            }

            return new Uri(requestUri, UriKind.RelativeOrAbsolute);
        }

        private HttpRequestMessage CreateRequestMessage(HttpMethod method, Uri requestUri)
        {
            if (method == null)
            {
                throw new ArgumentNullException(nameof(method));
            }

            if (requestUri == null)
            {
                throw new ArgumentNullException(nameof(requestUri));
            }

            return new HttpRequestMessage(method, requestUri)
            {
                Version = DefaultRequestVersion,
                VersionPolicy = DefaultVersionPolicy
            };
        }

        private void InitializeProxy(Func<MojaveProxyOptions> proxyResolver)
        {
            lock (_proxyLock)
            {
                _defaultProxyResolver = proxyResolver ?? (() => MojaveProxyOptions.NoProxy);
                _overrideProxyResolver = null;
                _staticProxyOptions = null;
                _proxyEnabled = true;
            }
        }

        private MojaveProxyOptions ResolveProxy()
        {
            lock (_proxyLock)
            {
                if (!_proxyEnabled)
                {
                    return MojaveProxyOptions.NoProxy;
                }

                if (_overrideProxyResolver != null)
                {
                    return InvokeResolver(_overrideProxyResolver);
                }

                if (_staticProxyOptions != null)
                {
                    return _staticProxyOptions;
                }

                return InvokeResolver(_defaultProxyResolver);
            }
        }

        private static MojaveProxyOptions InvokeResolver(Func<MojaveProxyOptions> resolver)
        {
            if (resolver == null)
            {
                return MojaveProxyOptions.NoProxy;
            }

            try
            {
                return resolver() ?? MojaveProxyOptions.NoProxy;
            }
            catch (Exception ex)
            {
                throw new ProxyException(
                    "The proxy resolver threw an exception.",
                    ProxyErrorReason.Unsupported,
                    innerException: ex);
            }
        }

        private void ClearConfiguredProxy()
        {
            _staticProxyOptions = null;
        }

        private void InitializeFingerprint(Func<JA3Fingerprint> fingerprintProvider)
        {
            lock (_fingerprintLock)
            {
                _fingerprintFactory = fingerprintProvider ?? ResolvePresetFactory();
                _currentFingerprint = null;
            }
        }

        private void EnsureJa3FingerprintingEnabled()
        {
            if (!_ja3FingerprintingEnabled)
            {
                throw new InvalidOperationException("JA3 spoofing is disabled for this client.");
            }
        }

        private JA3Fingerprint ResolveFingerprint()
        {
            lock (_fingerprintLock)
            {
                _currentFingerprint ??= (_fingerprintFactory ?? ResolvePresetFactory())();
                return _currentFingerprint;
            }
        }

        private Func<JA3Fingerprint> ResolvePresetFactory()
        {
            return () => JA3FingerprintFactory.GetFingerprint(
                _options.FingerprintPreset == Ja3Preset.Disabled
                    ? Ja3Preset.Default
                    : _options.FingerprintPreset);
        }

        private static MojaveHttpClientOptions BuildOptions(Action<MojaveHttpClientOptions> configure)
        {
            var options = new MojaveHttpClientOptions();
            configure?.Invoke(options);
            return options;
        }
    }
}
