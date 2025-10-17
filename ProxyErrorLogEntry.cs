using System;
using System.Net;

namespace Moljave.Http
{
    public sealed class ProxyErrorLogEntry
    {
        public ProxyErrorLogEntry(MojaveProxyOptions proxy, Exception exception, int attempt, bool willRetry)
        {
            Proxy = proxy ?? MojaveProxyOptions.NoProxy;
            Exception = exception ?? throw new ArgumentNullException(nameof(exception));
            Attempt = attempt;
            WillRetry = willRetry;

            if (exception is ProxyException proxyException)
            {
                Reason = proxyException.Reason;
                StatusCode = proxyException.StatusCode;
            }
        }

        public MojaveProxyOptions Proxy { get; }

        public ProxyDescriptor Descriptor => Proxy?.Descriptor;

        public Exception Exception { get; }

        public int Attempt { get; }

        public bool WillRetry { get; }

        public ProxyErrorReason? Reason { get; }

        public HttpStatusCode? StatusCode { get; }
    }
}
