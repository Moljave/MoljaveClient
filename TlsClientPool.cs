using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Linq;
using System.Net.Security;
using System.Runtime.CompilerServices;

namespace Moljave.Http
{
    internal static class TlsClientPool
    {
        private static readonly ConcurrentDictionary<string, ConcurrentQueue<TlsClient>> _pools = new();
        private static readonly ConcurrentDictionary<string, int> _poolSizes = new();

        public static TlsClientLease Rent(
            string host,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            ProxyDescriptor proxy,
            MojaveTlsSettings tlsSettings,
            RemoteCertificateValidationCallback certificateValidationCallback,
            int maxRequestsPerConnection,
            int maxPoolSize)
        {
            var key = BuildKey(host, port, useTls, fingerprint, proxy, tlsSettings, certificateValidationCallback);

            if (_pools.TryGetValue(key, out var queue))
            {
                while (queue.TryDequeue(out var pooledClient))
                {
                    DecrementSize(key);

                    if (pooledClient.IsConnectionReusable(maxRequestsPerConnection))
                    {
                        return new TlsClientLease(key, pooledClient, maxRequestsPerConnection, maxPoolSize, poolingEnabled: true);
                    }

                    pooledClient.Dispose();
                }
            }

            var client = new TlsClient(host, port, fingerprint, proxy, tlsSettings, certificateValidationCallback);
            return new TlsClientLease(key, client, maxRequestsPerConnection, maxPoolSize, poolingEnabled: true);
        }

        internal static void Return(string key, TlsClient client, int maxRequestsPerConnection, int maxPoolSize)
        {
            if (maxPoolSize <= 0 || !client.IsConnectionReusable(maxRequestsPerConnection))
            {
                client.Dispose();
                return;
            }

            var queue = _pools.GetOrAdd(key, _ => new ConcurrentQueue<TlsClient>());

            while (true)
            {
                var current = _poolSizes.GetOrAdd(key, 0);
                if (current >= maxPoolSize)
                {
                    client.Dispose();
                    return;
                }

                if (_poolSizes.TryUpdate(key, current + 1, current))
                {
                    queue.Enqueue(client);
                    return;
                }
            }
        }

        private static void DecrementSize(string key)
        {
            _poolSizes.AddOrUpdate(key, 0, static (_, current) => current > 0 ? current - 1 : 0);
        }

        private static string BuildKey(
            string host,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            ProxyDescriptor proxy,
            MojaveTlsSettings tlsSettings,
            RemoteCertificateValidationCallback certificateValidationCallback)
        {
            var fingerprintKey = fingerprint == null
                ? "nofp"
                : string.Join(
                    "|",
                    fingerprint.SslVersion.ToString(CultureInfo.InvariantCulture),
                    JoinInts(fingerprint.CipherSuites),
                    JoinInts(fingerprint.Extensions),
                    JoinInts(fingerprint.EllipticCurves),
                    JoinInts(fingerprint.EllipticCurvePointFormats));

            var tlsProtocols = tlsSettings?.EnabledProtocols?.ToString() ?? string.Empty;
            var applicationProtocols = tlsSettings?.ApplicationProtocols?.ToArray() ?? Array.Empty<string>();
            var applicationProtocolsKey = applicationProtocols.Length == 0
                ? string.Empty
                : string.Join("~", applicationProtocols);
            var validateCertificate = tlsSettings?.ValidateCertificate ?? false;
            var effectiveValidationCallback = validateCertificate
                ? tlsSettings?.CertificateValidationCallback ?? certificateValidationCallback
                : null;
            var validationCallbackKey = effectiveValidationCallback != null
                ? RuntimeHelpers.GetHashCode(effectiveValidationCallback).ToString(CultureInfo.InvariantCulture)
                : "nocb";

            var proxyKey = proxy == null
                ? "noproxy"
                : string.Join(
                    "|",
                    proxy.Scheme.ToString(),
                    proxy.Host,
                    proxy.Port.ToString(CultureInfo.InvariantCulture),
                    proxy.ResolveHostnamesRemotely ? "1" : "0",
                    proxy.Credentials?.UserName ?? string.Empty,
                    proxy.Credentials?.Password ?? string.Empty);

            return string.Join(
                "::",
                host,
                port.ToString(CultureInfo.InvariantCulture),
                useTls ? "tls" : "plain",
                fingerprintKey,
                tlsProtocols,
                applicationProtocolsKey,
                validateCertificate ? "validate" : "novalidate",
                validationCallbackKey,
                proxyKey);
        }

        private static string JoinInts(int[] values)
        {
            return values == null || values.Length == 0
                ? string.Empty
                : string.Join('-', values.Select(v => v.ToString(CultureInfo.InvariantCulture)));
        }
    }

    internal sealed class TlsClientLease : IDisposable
    {
        private readonly string _key;
        private readonly int _maxRequestsPerConnection;
        private readonly int _maxPoolSize;
        private readonly bool _poolingEnabled;
        private bool _disposed;
        private bool _returnToPool;

        internal TlsClientLease(string key, TlsClient client, int maxRequestsPerConnection, int maxPoolSize, bool poolingEnabled)
        {
            _key = key;
            Client = client ?? throw new ArgumentNullException(nameof(client));
            _maxRequestsPerConnection = maxRequestsPerConnection;
            _maxPoolSize = maxPoolSize;
            _poolingEnabled = poolingEnabled;
        }

        public TlsClient Client { get; }

        public void SetReturnToPool(bool value)
        {
            if (!_poolingEnabled)
            {
                _returnToPool = false;
                return;
            }

            _returnToPool = value;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            if (_poolingEnabled && _returnToPool)
            {
                TlsClientPool.Return(_key, Client, _maxRequestsPerConnection, _maxPoolSize);
            }
            else
            {
                Client.Dispose();
            }
        }

        public static TlsClientLease CreateUnpooled(TlsClient client)
        {
            return new TlsClientLease(key: null, client, maxRequestsPerConnection: 0, maxPoolSize: 0, poolingEnabled: false);
        }
    }
}
