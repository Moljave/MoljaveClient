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

    public sealed class ProxyDescriptor : IEquatable<ProxyDescriptor>
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

        public bool Equals(ProxyDescriptor other)
        {
            if (ReferenceEquals(this, other))
            {
                return true;
            }

            if (other is null)
            {
                return false;
            }

            return Scheme == other.Scheme &&
                   string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase) &&
                   Port == other.Port &&
                   ResolveHostnamesRemotely == other.ResolveHostnamesRemotely &&
                   CredentialsEqual(Credentials, other.Credentials);
        }

        public override bool Equals(object obj) => Equals(obj as ProxyDescriptor);

        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Scheme);
            hash.Add(Host, StringComparer.OrdinalIgnoreCase);
            hash.Add(Port);
            hash.Add(ResolveHostnamesRemotely);

            if (Credentials != null)
            {
                hash.Add(Credentials.UserName, StringComparer.Ordinal);
                hash.Add(Credentials.Password, StringComparer.Ordinal);
                hash.Add(Credentials.Domain, StringComparer.Ordinal);
            }
            else
            {
                hash.Add(0);
            }

            return hash.ToHashCode();
        }

        private static bool CredentialsEqual(NetworkCredential first, NetworkCredential second)
        {
            if (ReferenceEquals(first, second))
            {
                return true;
            }

            if (first == null || second == null)
            {
                return false;
            }

            return string.Equals(first.UserName, second.UserName, StringComparison.Ordinal) &&
                   string.Equals(first.Password, second.Password, StringComparison.Ordinal) &&
                   string.Equals(first.Domain, second.Domain, StringComparison.Ordinal);
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
            var scheme = address.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
                ? ProxyScheme.Https
                : ProxyScheme.Http;

            var credentials = ExtractCredentials(proxy, address);
            var descriptor = new ProxyDescriptor(scheme, address.Host, address.Port, credentials);
            return new MojaveProxyOptions(descriptor);
        }

        internal static MojaveProxyOptions FromWebProxy(WebProxy proxy, IProxyRotationListener rotationListener)
        {
            if (proxy?.Address == null)
            {
                return NoProxy;
            }

            var address = proxy.Address;
            var scheme = address.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
                ? ProxyScheme.Https
                : ProxyScheme.Http;

            var credentials = ExtractCredentials(proxy, address);
            var descriptor = new ProxyDescriptor(scheme, address.Host, address.Port, credentials);
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
    }
}
