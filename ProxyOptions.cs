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
                Scheme = GetSchemeString(Scheme, ResolveHostnamesRemotely),
                Host = Host,
                Port = Port > 0 ? Port : GetDefaultPort(Scheme)
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
            : this(descriptor, null)
        {
        }

        private MojaveProxyOptions(ProxyDescriptor descriptor, IProxyRotationListener rotationListener)
        {
            Descriptor = descriptor;
            RotationListener = rotationListener;
        }

        public ProxyDescriptor Descriptor { get; }
        public bool HasProxy => Descriptor != null;

        internal IProxyRotationListener RotationListener { get; }

        public static MojaveProxyOptions FromDescriptor(ProxyDescriptor descriptor) =>
            descriptor == null ? NoProxy : new MojaveProxyOptions(descriptor);

        internal static MojaveProxyOptions CreateWithListener(
            ProxyDescriptor descriptor,
            IProxyRotationListener rotationListener) =>
            descriptor == null ? NoProxy : new MojaveProxyOptions(descriptor, rotationListener);

        public static MojaveProxyOptions FromWebProxy(WebProxy proxy)
        {
            if (proxy?.Address == null)
            {
                return NoProxy;
            }

            var address = proxy.Address;
            if (string.IsNullOrWhiteSpace(address.Host))
            {
                return NoProxy;
            }
            var scheme = ParseScheme(address?.Scheme, out var resolveRemotely);
            var port = address?.Port ?? -1;
            if (port <= 0)
            {
                port = GetDefaultPort(scheme);
            }

            var credentials = ExtractCredentials(proxy, address);
            var descriptor = new ProxyDescriptor(scheme, address.Host, port, credentials, resolveRemotely);
            return new MojaveProxyOptions(descriptor);
        }

        internal static MojaveProxyOptions FromWebProxy(WebProxy proxy, IProxyRotationListener rotationListener)
        {
            if (proxy?.Address == null)
            {
                return NoProxy;
            }

            var address = proxy.Address;
            if (string.IsNullOrWhiteSpace(address.Host))
            {
                return NoProxy;
            }
            var scheme = ParseScheme(address?.Scheme, out var resolveRemotely);
            var port = address?.Port ?? -1;
            if (port <= 0)
            {
                port = GetDefaultPort(scheme);
            }

            var credentials = ExtractCredentials(proxy, address);
            var descriptor = new ProxyDescriptor(scheme, address.Host, port, credentials, resolveRemotely);
            return new MojaveProxyOptions(descriptor, rotationListener);
        }

        private static NetworkCredential ExtractCredentials(WebProxy proxy, Uri address)
        {
            if (proxy == null)
            {
                return null;
            }

            var credentials = proxy.Credentials;

            NetworkCredential Clone(NetworkCredential source) => source == null
                ? null
                : new NetworkCredential(source.UserName, source.Password, source.Domain);

            if (credentials is NetworkCredential direct)
            {
                return Clone(direct);
            }

            if (credentials != null && address != null)
            {
                static NetworkCredential TryGet(ICredentials provider, Uri uri, string authType)
                    => provider?.GetCredential(uri, authType);

                var resolved = TryGet(credentials, address, "Basic")
                    ?? TryGet(credentials, address, "Digest")
                    ?? TryGet(credentials, address, "NTLM")
                    ?? TryGet(credentials, address, "Negotiate")
                    ?? TryGet(credentials, address, null);

                if (resolved != null)
                {
                    return Clone(resolved);
                }
            }

            if (proxy.UseDefaultCredentials)
            {
                var defaults = CredentialCache.DefaultNetworkCredentials;
                if (defaults != null)
                {
                    return Clone(defaults);
                }
            }

            return null;
        }

        private static ProxyScheme ParseScheme(string scheme, out bool resolveRemotely)
        {
            resolveRemotely = false;

            if (string.IsNullOrWhiteSpace(scheme))
            {
                return ProxyScheme.Http;
            }

            switch (scheme.ToLowerInvariant())
            {
                case "https":
                    return ProxyScheme.Https;
                case "socks":
                case "socks5":
                    return ProxyScheme.Socks5;
                case "socks5h":
                    resolveRemotely = true;
                    return ProxyScheme.Socks5;
                case "socks4":
                    return ProxyScheme.Socks4;
                case "socks4a":
                    resolveRemotely = true;
                    return ProxyScheme.Socks4a;
                default:
                    return ProxyScheme.Http;
            }
        }

        private static string GetSchemeString(ProxyScheme scheme, bool resolveRemotely)
        {
            return scheme switch
            {
                ProxyScheme.Https => Uri.UriSchemeHttps,
                ProxyScheme.Socks4 when resolveRemotely => "socks4a",
                ProxyScheme.Socks4 => "socks4",
                ProxyScheme.Socks4a => "socks4a",
                ProxyScheme.Socks5 when resolveRemotely => "socks5h",
                ProxyScheme.Socks5 => "socks5",
                _ => Uri.UriSchemeHttp
            };
        }

        private static int GetDefaultPort(ProxyScheme scheme)
        {
            return scheme switch
            {
                ProxyScheme.Https => 443,
                ProxyScheme.Socks4 or ProxyScheme.Socks4a or ProxyScheme.Socks5 => 1080,
                _ => 80
            };
        }
    }
}
