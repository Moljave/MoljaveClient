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
        private const int MinimumSocketBufferSize = 1024;
        private const int MinimumMaxConnectionsPerHost = 1;

        private long _defaultTimeoutTicks = TimeSpan.FromSeconds(30).Ticks;
        private int _allowAutoRedirect = 1;
        private int _maxAutomaticRedirections = 10;
        private int _maxConnectionRetries = 2;
        private long _connectionRetryDelayTicks = TimeSpan.FromMilliseconds(150).Ticks;
        private int _maxConnectionsPerHost = 256;
        private int _socketBufferSize = 8 * 1024;
        private int _forceConnectionCloseAfterRequest = 0;

        public Func<JA3Fingerprint> FingerprintProvider { get; set; } =
            () => JA3FingerprintFactory.GetFingerprint(BrowserJa3Profile.Chrome);

        public bool EnableJa3Fingerprinting { get; set; } = true;

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

        public int SocketBufferSize
        {
            get => Volatile.Read(ref _socketBufferSize);
            set
            {
                var effective = value < 0 ? 0 : value;
                Interlocked.Exchange(ref _socketBufferSize, effective);
            }
        }

        public bool ForceCloseConnectionsAfterRequest
        {
            get => Volatile.Read(ref _forceConnectionCloseAfterRequest) == 1;
            set => Interlocked.Exchange(ref _forceConnectionCloseAfterRequest, value ? 1 : 0);
        }

        public IList<Func<DelegatingHandler>> DelegatingHandlerFactories { get; } = new List<Func<DelegatingHandler>>();

        public RemoteCertificateValidationCallback CertificateValidationCallback { get; set; }
            = (_, _, _, _) => true;

        internal bool TryReduceSocketBufferSize(int observedValue)
        {
            while (true)
            {
                var current = Volatile.Read(ref _socketBufferSize);

                if (current <= 0)
                {
                    return false;
                }

                if (observedValue > 0 && current < observedValue)
                {
                    return false;
                }

                int next;
                if (current <= MinimumSocketBufferSize)
                {
                    next = 0;
                }
                else
                {
                    next = Math.Max(MinimumSocketBufferSize, current / 2);
                    if (next == current)
                    {
                        next = MinimumSocketBufferSize;
                    }
                }

                if (Interlocked.CompareExchange(ref _socketBufferSize, next, current) == current)
                {
                    return true;
                }
            }
        }

        internal bool TryReduceMaxConnectionsPerHost(int observedValue)
        {
            while (true)
            {
                var current = Volatile.Read(ref _maxConnectionsPerHost);

                if (current <= MinimumMaxConnectionsPerHost)
                {
                    return false;
                }

                if (observedValue > 0 && current < observedValue)
                {
                    return false;
                }

                var next = Math.Max(MinimumMaxConnectionsPerHost, current / 2);
                if (next == current)
                {
                    next = MinimumMaxConnectionsPerHost;
                    if (next == current)
                    {
                        return false;
                    }
                }

                if (Interlocked.CompareExchange(ref _maxConnectionsPerHost, next, current) == current)
                {
                    return true;
                }
            }
        }

        internal bool TryEnableForceCloseConnections()
        {
            while (true)
            {
                var current = Volatile.Read(ref _forceConnectionCloseAfterRequest);
                if (current == 1)
                {
                    return false;
                }

                if (Interlocked.CompareExchange(ref _forceConnectionCloseAfterRequest, 1, current) == current)
                {
                    return true;
                }
            }
        }

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
        public Func<int, MojaveProxyOptions> ProxySelector { get; set; }
        public TimeSpan? Timeout { get; set; }
        public bool? AllowAutoRedirect { get; set; }
        public int? MaxAutomaticRedirections { get; set; }
        public MojaveCookieManager CookieManager { get; set; }
        public int? MaxConnectionRetries { get; set; }
        public TimeSpan? RetryDelay { get; set; }
        public bool? ForceCloseConnectionsAfterRequest { get; set; }
        public int? MaxConnectionsPerHost { get; set; }
        public int? SocketBufferSize { get; set; }
        public object SessionAffinityKey { get; set; }

        internal MojaveRequestOptions Clone() => new()
        {
            Fingerprint = Fingerprint,
            TlsSettings = TlsSettings,
            Proxy = Proxy,
            ProxySelector = ProxySelector,
            Timeout = Timeout,
            AllowAutoRedirect = AllowAutoRedirect,
            MaxAutomaticRedirections = MaxAutomaticRedirections,
            CookieManager = CookieManager,
            MaxConnectionRetries = MaxConnectionRetries,
            RetryDelay = RetryDelay,
            ForceCloseConnectionsAfterRequest = ForceCloseConnectionsAfterRequest,
            MaxConnectionsPerHost = MaxConnectionsPerHost,
            SocketBufferSize = SocketBufferSize,
            SessionAffinityKey = SessionAffinityKey
        };
    }

    public sealed class MojaveTlsSettings : IEquatable<MojaveTlsSettings>
    {
        public static MojaveTlsSettings Default { get; } = new();

        public SslProtocols? EnabledProtocols { get; set; }
        public IEnumerable<string> ApplicationProtocols { get; set; }
        public bool ValidateCertificate { get; set; } = false;
        public RemoteCertificateValidationCallback CertificateValidationCallback { get; set; }
            = (_, _, _, _) => true;

        public bool Equals(MojaveTlsSettings other)
        {
            if (ReferenceEquals(this, other))
            {
                return true;
            }

            if (other is null)
            {
                return false;
            }

            return Nullable.Equals(EnabledProtocols, other.EnabledProtocols) &&
                   ProtocolsEqual(ApplicationProtocols, other.ApplicationProtocols) &&
                   ValidateCertificate == other.ValidateCertificate &&
                   Equals(CertificateValidationCallback, other.CertificateValidationCallback);
        }

        public override bool Equals(object obj) => Equals(obj as MojaveTlsSettings);

        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(EnabledProtocols);
            AddProtocolsHash(ref hash, ApplicationProtocols);
            hash.Add(ValidateCertificate);
            hash.Add(CertificateValidationCallback);
            return hash.ToHashCode();
        }

        private static bool ProtocolsEqual(IEnumerable<string> first, IEnumerable<string> second)
        {
            if (ReferenceEquals(first, second))
            {
                return true;
            }

            if (first == null || second == null)
            {
                return first == null && second == null;
            }

            using var firstEnumerator = NormalizeProtocols(first).GetEnumerator();
            using var secondEnumerator = NormalizeProtocols(second).GetEnumerator();

            while (true)
            {
                var hasFirst = firstEnumerator.MoveNext();
                var hasSecond = secondEnumerator.MoveNext();

                if (!hasFirst || !hasSecond)
                {
                    return hasFirst == hasSecond;
                }

                if (!string.Equals(firstEnumerator.Current, secondEnumerator.Current, StringComparison.Ordinal))
                {
                    return false;
                }
            }
        }

        private static IEnumerable<string> NormalizeProtocols(IEnumerable<string> protocols)
        {
            if (protocols == null)
            {
                return Array.Empty<string>();
            }

            return protocols is string[] array
                ? array
                : protocols is IList<string> list
                    ? list
                    : new List<string>(protocols);
        }

        private static void AddProtocolsHash(ref HashCode hash, IEnumerable<string> protocols)
        {
            if (protocols == null)
            {
                hash.Add(0);
                return;
            }

            foreach (var protocol in NormalizeProtocols(protocols))
            {
                hash.Add(protocol, StringComparer.Ordinal);
            }
        }
    }
}
