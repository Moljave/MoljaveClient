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

        public void UseProxy(MojaveProxyOptions proxyOptions)
        {
            if (proxyOptions == null)
            {
                throw new ArgumentNullException(nameof(proxyOptions));
            }

            lock (_proxyLock)
            {
                _options.ProxyResolver = () => proxyOptions;
            }
        }

        public void UseProxy(WebProxy proxy)
        {
            lock (_proxyLock)
            {
                _options.ProxyResolver = proxy != null
                    ? () => MojaveProxyOptions.FromWebProxy(proxy)
                    : () => MojaveProxyOptions.NoProxy;
            }
        }

        public void UseProxyResolver(Func<MojaveProxyOptions> resolver)
        {
            lock (_proxyLock)
            {
                _options.ProxyResolver = resolver ?? (() => MojaveProxyOptions.NoProxy);
            }
        }

        public void ClearProxy() => UseProxy((WebProxy)null);

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
