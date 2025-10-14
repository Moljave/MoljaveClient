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
        private bool _disposed;

        public MojaveHttpClient(
            JA3Fingerprint ja3Fingerprint = null,
            CookieContainer cookieContainer = null,
            WebProxy proxy = null)
            : this(new MojaveHttpClientOptions
            {
                FingerprintProvider = () => ja3Fingerprint ?? JA3FingerprintFactory.GetFingerprint(BrowserJa3Profile.Chrome),
                CookieContainer = cookieContainer ?? new CookieContainer(),
                ProxyResolver = proxy != null
                    ? () => MojaveProxyOptions.FromWebProxy(proxy)
                    : () => MojaveProxyOptions.NoProxy
            })
        {
        }

        public MojaveHttpClient(MojaveHttpClientOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
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
            get => _options.CookieContainer;
            set => _options.CookieContainer = value ?? new CookieContainer();
        }

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
    }
}
