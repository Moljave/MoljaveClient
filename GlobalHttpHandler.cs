using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    internal static class GlobalHttpHandler
    {
        private static readonly MojaveHttpClientOptions _globalOptions;
        private static readonly HttpMessageHandler _pipeline;
        private static readonly HttpMessageInvoker _invoker;

        static GlobalHttpHandler()
        {
            _globalOptions = new MojaveHttpClientOptions
            {
                MaxConnectionsPerHost = 65000
            };

            _pipeline = _globalOptions.BuildHandlerPipeline();
            _invoker = new HttpMessageInvoker(_pipeline, disposeHandler: true);
        }

        public static Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => _invoker.SendAsync(request, cancellationToken);

        public static void ClearSessionConnections(object affinityKey)
        {
            if (affinityKey == null)
            {
                return;
            }

            TlsConnectionPool.Shared.ClearConnectionsForSession(affinityKey);
        }
    }
}
