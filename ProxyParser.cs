using System;
using System.Net;
using System.Text.RegularExpressions;

namespace Moljave.Http
{
    public static class ProxyParser
    {
        private static readonly Regex BasicProxyRegex = new(
            "^(?:(?<scheme>[a-zA-Z0-9]+)://)?(?:(?<user>[^:@]+)(?::(?<pass>[^@]+))?@)?(?<host>\\[[^\\]]+\\]|[^:]+)(?::(?<port>\\d+))?$",
            RegexOptions.Compiled);

        public static bool TryParse(string raw, out MojaveProxyOptions options)
        {
            options = MojaveProxyOptions.NoProxy;

            if (string.IsNullOrWhiteSpace(raw))
            {
                return false;
            }

            raw = raw.Trim();
            var match = BasicProxyRegex.Match(raw);
            if (!match.Success)
            {
                return false;
            }

            var schemeToken = match.Groups["scheme"].Value;
            var host = match.Groups["host"].Value;
            if (host.StartsWith("[") && host.EndsWith("]"))
            {
                host = host[1..^1];
            }
            var portText = match.Groups["port"].Value;
            var user = match.Groups["user"].Value;
            var pass = match.Groups["pass"].Value;

            if (string.IsNullOrWhiteSpace(host))
            {
                return false;
            }

            var scheme = ParseScheme(schemeToken, out bool resolveRemotely);
            if (!int.TryParse(portText, out var port))
            {
                port = scheme switch
                {
                    ProxyScheme.Https => 443,
                    ProxyScheme.Socks4 or ProxyScheme.Socks4a or ProxyScheme.Socks5 => 1080,
                    _ => 80
                };
            }

            if (port <= 0 || port > 65535)
            {
                return false;
            }

            NetworkCredential credentials = null;
            if (!string.IsNullOrWhiteSpace(user))
            {
                credentials = new NetworkCredential(Uri.UnescapeDataString(user), Uri.UnescapeDataString(pass));
            }

            var descriptor = new ProxyDescriptor(scheme, host, port, credentials, resolveRemotely);
            options = MojaveProxyOptions.FromDescriptor(descriptor);
            return true;
        }

        private static ProxyScheme ParseScheme(string scheme, out bool resolveRemotely)
        {
            resolveRemotely = false;
            if (string.IsNullOrWhiteSpace(scheme))
            {
                return ProxyScheme.Http;
            }

            scheme = scheme.ToLowerInvariant();
            return scheme switch
            {
                "http" => ProxyScheme.Http,
                "https" => ProxyScheme.Https,
                "socks" => ProxyScheme.Socks5,
                "socks5" => ProxyScheme.Socks5,
                "socks5h" => SetResolve(true, ProxyScheme.Socks5, out resolveRemotely),
                "socks4" => ProxyScheme.Socks4,
                "socks4a" => SetResolve(true, ProxyScheme.Socks4a, out resolveRemotely),
                _ => ProxyScheme.Http
            };
        }

        private static ProxyScheme SetResolve(bool value, ProxyScheme scheme, out bool resolveRemotely)
        {
            resolveRemotely = value;
            return scheme;
        }
    }
}
