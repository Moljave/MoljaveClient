using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Threading;

namespace Moljave.Http
{
    public sealed class MojaveHttpClientOptions
    {
        private long _defaultTimeoutTicks = TimeSpan.FromSeconds(30).Ticks;
        private int _allowAutoRedirect = 1;
        private int _maxAutomaticRedirections = 10;
        private int _maxConnectionRetries = 2;
        private long _connectionRetryDelayTicks = TimeSpan.FromMilliseconds(150).Ticks;
        private int _maxConnectionsPerHost = 15000;

        public Func<JA3Fingerprint> FingerprintProvider { get; set; } =
            () => JA3FingerprintFactory.GetFingerprint(BrowserJa3Profile.Chrome);

        public Func<MojaveTlsSettings> TlsSettingsProvider { get; set; } = () => MojaveTlsSettings.Default;

        public Func<MojaveProxyOptions> ProxyResolver { get; set; }
            = () => MojaveProxyOptions.NoProxy;

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

        public bool AllowAutoRedirect
        {
            get => Volatile.Read(ref _allowAutoRedirect) == 1;
            set => Interlocked.Exchange(ref _allowAutoRedirect, value ? 1 : 0);
        }

        public int MaxAutomaticRedirections
        {
            get => Volatile.Read(ref _maxAutomaticRedirections);
            set
            {
                var sanitized = value < 0 ? 0 : value;
                Interlocked.Exchange(ref _maxAutomaticRedirections, sanitized);
            }
        }

        public TimeSpan DefaultTimeout
        {
            get => TimeSpan.FromTicks(Volatile.Read(ref _defaultTimeoutTicks));
            set
            {
                var effective = value <= TimeSpan.Zero ? TimeSpan.FromSeconds(30) : value;
                Interlocked.Exchange(ref _defaultTimeoutTicks, effective.Ticks);
            }
        }

        public int MaxConnectionRetries
        {
            get => Volatile.Read(ref _maxConnectionRetries);
            set
            {
                var effective = value < 0 ? 0 : value;
                Interlocked.Exchange(ref _maxConnectionRetries, effective);
            }
        }

        public TimeSpan ConnectionRetryDelay
        {
            get => TimeSpan.FromTicks(Volatile.Read(ref _connectionRetryDelayTicks));
            set
            {
                var effective = value < TimeSpan.Zero ? TimeSpan.Zero : value;
                Interlocked.Exchange(ref _connectionRetryDelayTicks, effective.Ticks);
            }
        }

        public int MaxConnectionsPerHost
        {
            get => Volatile.Read(ref _maxConnectionsPerHost);
            set
            {
                var effective = value <= 0 ? 1 : value;
                Interlocked.Exchange(ref _maxConnectionsPerHost, effective);
            }
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
