using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;

namespace Moljave.Http
{
    public sealed class MojaveHttpClientOptions
    {
        private TimeSpan _defaultTimeout = TimeSpan.FromSeconds(30);
        private int _maxAutomaticRedirections = 10;
        private int _maxConnectionRetries = 2;
        private TimeSpan _connectionRetryDelay = TimeSpan.FromMilliseconds(150);
        private int _maxConnectionsPerHost = 6000;

        public Func<JA3Fingerprint> FingerprintProvider { get; set; } =
            () => JA3FingerprintFactory.GetFingerprint(BrowserJa3Profile.Chrome);

        public Func<MojaveTlsSettings> TlsSettingsProvider { get; set; } = () => MojaveTlsSettings.Default;

        public Func<MojaveProxyOptions> ProxyResolver { get; set; }
            = () => MojaveProxyOptions.NoProxy;

        public Action<ProxyErrorLogEntry> ProxyErrorLogger { get; set; }
            = null;

        private MojaveCookieManager _cookieManager = new();

        public MojaveCookieManager CookieManager
        {
            get => _cookieManager;
            set => _cookieManager = value ?? new MojaveCookieManager();
        }

        public CookieContainer CookieContainer
        {
            get => _cookieManager?.GetInternalContainer();
            set => (_cookieManager ??= new MojaveCookieManager()).ReplaceWith(value ?? new CookieContainer());
        }

        public bool AllowAutoRedirect { get; set; } = true;

        public int MaxAutomaticRedirections
        {
            get => _maxAutomaticRedirections;
            set => _maxAutomaticRedirections = value < 0 ? 0 : value;
        }

        public TimeSpan DefaultTimeout
        {
            get => _defaultTimeout;
            set => _defaultTimeout = value <= TimeSpan.Zero ? TimeSpan.FromSeconds(30) : value;
        }

        public int MaxConnectionRetries
        {
            get => _maxConnectionRetries;
            set => _maxConnectionRetries = value < 0 ? 0 : value;
        }

        public TimeSpan ConnectionRetryDelay
        {
            get => _connectionRetryDelay;
            set => _connectionRetryDelay = value < TimeSpan.Zero ? TimeSpan.Zero : value;
        }

        public int MaxConnectionsPerHost
        {
            get => _maxConnectionsPerHost;
            set => _maxConnectionsPerHost = value <= 0 ? 1 : value;
        }

        public IList<Func<DelegatingHandler>> DelegatingHandlerFactories { get; } = new List<Func<DelegatingHandler>>();

        public RemoteCertificateValidationCallback CertificateValidationCallback { get; set; }
            = (_, _, _, _) => true;

        internal HttpMessageHandler BuildHandlerPipeline()
        {
            HttpMessageHandler current = new MojaveHttpMessageHandler(this);

            if (DelegatingHandlerFactories == null || DelegatingHandlerFactories.Count == 0)
            {
                return current;
            }

            for (int i = DelegatingHandlerFactories.Count - 1; i >= 0; i--)
            {
                var factory = DelegatingHandlerFactories[i];
                if (factory == null)
                {
                    continue;
                }

                var handler = factory();
                if (handler == null)
                {
                    continue;
                }
                handler.InnerHandler = current;
                current = handler;
            }

            return current;
        }
    }

    public sealed class MojaveRequestOptions
    {
        public JA3Fingerprint Fingerprint { get; set; }
        public MojaveTlsSettings TlsSettings { get; set; }
        public MojaveProxyOptions Proxy { get; set; }
        public TimeSpan? Timeout { get; set; }
        public bool? AllowAutoRedirect { get; set; }
        public int? MaxAutomaticRedirections { get; set; }
        public MojaveCookieManager CookieManager { get; set; }
        public int? MaxConnectionRetries { get; set; }
        public TimeSpan? RetryDelay { get; set; }

        internal MojaveRequestOptions Clone() => new()
        {
            Fingerprint = Fingerprint,
            TlsSettings = TlsSettings,
            Proxy = Proxy,
            Timeout = Timeout,
            AllowAutoRedirect = AllowAutoRedirect,
            MaxAutomaticRedirections = MaxAutomaticRedirections,
            CookieManager = CookieManager,
            MaxConnectionRetries = MaxConnectionRetries,
            RetryDelay = RetryDelay
        };
    }

    public sealed class MojaveTlsSettings
    {
        public static MojaveTlsSettings Default { get; } = new();

        public SslProtocols? EnabledProtocols { get; set; }
        public IEnumerable<string> ApplicationProtocols { get; set; }
        public bool ValidateCertificate { get; set; } = false;
        public RemoteCertificateValidationCallback CertificateValidationCallback { get; set; }
            = (_, _, _, _) => true;
    }
}
