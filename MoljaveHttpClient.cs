using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    public sealed class MojaveHttpClient : IDisposable
    {
        private readonly MojaveHttpClientOptions _options;
        private readonly HttpMessageInvoker _invoker;
        private readonly MojaveCookieManager _cookieManager;
        private readonly object _fingerprintLock = new();
        private readonly object _proxyLock = new();
        private Func<JA3Fingerprint> _fingerprintFactory;
        private JA3Fingerprint _currentFingerprint;
        private Func<MojaveProxyOptions> _defaultProxyResolver;
        private Func<MojaveProxyOptions> _overrideProxyResolver;
        private MojaveProxyOptions _staticProxyOptions;
        private bool _proxyEnabled = true;
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
            _cookieManager = _options.CookieManager ?? new MojaveCookieManager();
            _options.CookieManager = _cookieManager;

            InitializeFingerprint(_options.FingerprintProvider);
            _options.FingerprintProvider = ResolveFingerprint;

            InitializeProxy(_options.ProxyResolver);
            _options.ProxyResolver = ResolveProxy;

            _invoker = new HttpMessageInvoker(_options.BuildHandlerPipeline(), disposeHandler: true);
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

        public TimeSpan DefaultTimeout
        {
            get => _options.DefaultTimeout;
            set => _options.DefaultTimeout = value;
        }

        public CookieContainer CookieContainer
        {
            get => _cookieManager.GetInternalContainer();
            set => _cookieManager.ReplaceWith(value ?? new CookieContainer());
        }

        public MojaveCookieManager CookieManager => _cookieManager;

        public void RotateFingerprint()
        {
            lock (_fingerprintLock)
            {
                _currentFingerprint = (_fingerprintFactory ?? DefaultFingerprintFactory)();
            }
        }

        public void UseFingerprintProvider(Func<JA3Fingerprint> provider, bool rotateImmediately = true)
        {
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
            _invoker.Dispose();
        }

        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
            => SendAsync(request, _options.DefaultTimeout, cancellationToken);

        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(MojaveHttpClient));
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            request.ConfigureMojaveOptions(options =>
            {
                if (!options.Timeout.HasValue)
                {
                    options.Timeout = timeout;
                }
            });

            return _invoker.SendAsync(request, cancellationToken);
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

        private MojaveProxyOptions InvokeResolver(Func<MojaveProxyOptions> resolver)
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
                var proxyException = new ProxyException(
                    "The proxy resolver threw an exception.",
                    ProxyErrorReason.Unsupported,
                    innerException: ex);

                LogProxyError(MojaveProxyOptions.NoProxy, proxyException);
                throw proxyException;
            }
        }

        private void LogProxyError(MojaveProxyOptions proxyOptions, Exception exception, int attempt = -1, bool willRetry = false)
        {
            if (exception == null)
            {
                return;
            }

            var logger = _options.ProxyErrorLogger;
            if (logger == null)
            {
                return;
            }

            try
            {
                logger(new ProxyErrorLogEntry(proxyOptions, exception, attempt, willRetry));
            }
            catch
            {
                // Ignore logging failures to avoid interfering with request execution.
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
                _fingerprintFactory = fingerprintProvider ?? DefaultFingerprintFactory;
                _currentFingerprint = _fingerprintFactory();
            }
        }

        private JA3Fingerprint ResolveFingerprint()
        {
            lock (_fingerprintLock)
            {
                _currentFingerprint ??= (_fingerprintFactory ?? DefaultFingerprintFactory)();
                return _currentFingerprint;
            }
        }

        private static MojaveHttpClientOptions BuildOptions(Action<MojaveHttpClientOptions> configure)
        {
            var options = new MojaveHttpClientOptions();
            configure?.Invoke(options);
            return options;
        }

        private static JA3Fingerprint DefaultFingerprintFactory()
            => JA3FingerprintFactory.GetFingerprint(BrowserJa3Profile.Chrome);
    }
}
