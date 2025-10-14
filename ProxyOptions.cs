using System;
using System.Net;

namespace Moljave.Http
{
    public enum ProxyScheme
    {
        Http,
        Https,
        Socks4,
        Socks4a,
        Socks5
    }

    public sealed class ProxyDescriptor
    {
        public ProxyDescriptor(ProxyScheme scheme, string host, int port, NetworkCredential credentials = null, bool resolveHostnamesRemotely = false)
        {
            Scheme = scheme;
            Host = host ?? throw new ArgumentNullException(nameof(host));
            Port = port;
            Credentials = credentials;
            ResolveHostnamesRemotely = resolveHostnamesRemotely;
        }

        public ProxyScheme Scheme { get; }
        public string Host { get; }
        public int Port { get; }
        public NetworkCredential Credentials { get; }
        public bool ResolveHostnamesRemotely { get; }

        public WebProxy ToWebProxy()
        {
            var uriBuilder = new UriBuilder
            {
                Scheme = Scheme == ProxyScheme.Https ? Uri.UriSchemeHttps : Uri.UriSchemeHttp,
                Host = Host,
                Port = Port
            };

            var proxy = new WebProxy(uriBuilder.Uri);
            if (Credentials != null)
            {
                proxy.Credentials = new NetworkCredential(Credentials.UserName, Credentials.Password);
            }

            return proxy;
        }
    }

    public sealed class MojaveProxyOptions
    {
        public static MojaveProxyOptions NoProxy { get; } = new(null);

        private MojaveProxyOptions(ProxyDescriptor descriptor)
        {
            Descriptor = descriptor;
        }

        public ProxyDescriptor Descriptor { get; }
        public bool HasProxy => Descriptor != null;

        public static MojaveProxyOptions FromDescriptor(ProxyDescriptor descriptor) =>
            descriptor == null ? NoProxy : new MojaveProxyOptions(descriptor);

        public static MojaveProxyOptions FromWebProxy(WebProxy proxy)
        {
            if (proxy == null)
            {
                return NoProxy;
            }

            var scheme = proxy.Address.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
                ? ProxyScheme.Https
                : ProxyScheme.Http;

            NetworkCredential credentials = null;
            if (proxy.Credentials is NetworkCredential creds)
            {
                credentials = new NetworkCredential(creds.UserName, creds.Password);
            }

            var descriptor = new ProxyDescriptor(scheme, proxy.Address.Host, proxy.Address.Port, credentials);
            return new MojaveProxyOptions(descriptor);
        }
    }
}
