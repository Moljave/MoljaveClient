using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    internal sealed class TlsConnectionPool
    {
        private static readonly Lazy<TlsConnectionPool> _lazy = new(() => new TlsConnectionPool());

        private readonly ConcurrentDictionary<PoolKey, PoolState> _states = new();

        public static TlsConnectionPool Shared => _lazy.Value;

        private TlsConnectionPool()
        {
        }

        public async Task<TlsClientLease> RentAsync(
            string host,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            ProxyDescriptor proxyDescriptor,
            RemoteCertificateValidationCallback certificateValidationCallback,
            int maxConnections,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(host))
            {
                throw new ArgumentNullException(nameof(host));
            }

            maxConnections = Math.Max(1, maxConnections);

            var key = new PoolKey(
                host,
                port,
                useTls,
                BuildFingerprintSignature(fingerprint),
                BuildTlsSignature(tlsSettings),
                BuildProxySignature(proxyDescriptor));

            var state = _states.GetOrAdd(key, _ => new PoolState());
            var semaphore = state.GetSemaphore(maxConnections);

            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                while (state.Queue.TryDequeue(out var existing))
                {
                    if (existing != null && existing.IsReusable)
                    {
                        return new TlsClientLease(this, key, state, semaphore, existing);
                    }

                    existing?.Dispose();
                }

                var client = new TlsClient(
                    host,
                    port,
                    fingerprint,
                    proxyDescriptor,
                    tlsSettings,
                    certificateValidationCallback);

                return new TlsClientLease(this, key, state, semaphore, client);
            }
            catch
            {
                semaphore.Release();
                throw;
            }
        }

        internal void Return(
            PoolKey key,
            PoolState state,
            SemaphoreSlim semaphore,
            TlsClient client,
            bool canReuse)
        {
            try
            {
                if (canReuse && client != null && client.IsReusable)
                {
                    state.Queue.Enqueue(client);
                }
                else
                {
                    client?.Dispose();
                }
            }
            finally
            {
                semaphore.Release();
            }
        }

        private static string BuildFingerprintSignature(JA3Fingerprint fingerprint)
        {
            if (fingerprint == null)
            {
                return "none";
            }

            return string.Join('|', new[]
            {
                fingerprint.SslVersion.ToString(),
                string.Join('-', fingerprint.CipherSuites ?? Array.Empty<int>()),
                string.Join('-', fingerprint.Extensions ?? Array.Empty<int>()),
                string.Join('-', fingerprint.EllipticCurves ?? Array.Empty<int>()),
                string.Join('-', fingerprint.EllipticCurvePointFormats ?? Array.Empty<int>())
            });
        }

        private static string BuildTlsSignature(MojaveTlsSettings settings)
        {
            if (settings == null)
            {
                return "default";
            }

            var protocols = settings.ApplicationProtocols != null
                ? string.Join(',', settings.ApplicationProtocols)
                : string.Empty;

            return string.Join('|', new[]
            {
                settings.EnabledProtocols?.ToString() ?? string.Empty,
                protocols,
                settings.ValidateCertificate.ToString()
            });
        }

        private static string BuildProxySignature(ProxyDescriptor descriptor)
        {
            if (descriptor == null)
            {
                return "no-proxy";
            }

            var credential = descriptor.Credentials;
            var username = credential?.UserName ?? string.Empty;
            var password = credential?.Password ?? string.Empty;

            return string.Join('|', new[]
            {
                descriptor.Scheme.ToString(),
                descriptor.Host,
                descriptor.Port.ToString(),
                username,
                password,
                descriptor.ResolveHostnamesRemotely.ToString()
            });
        }

        internal readonly struct PoolKey : IEquatable<PoolKey>
        {
            public PoolKey(string host, int port, bool useTls, string fingerprintSignature, string tlsSignature, string proxySignature)
            {
                Host = host;
                Port = port;
                UseTls = useTls;
                FingerprintSignature = fingerprintSignature;
                TlsSignature = tlsSignature;
                ProxySignature = proxySignature;
            }

            public string Host { get; }
            public int Port { get; }
            public bool UseTls { get; }
            public string FingerprintSignature { get; }
            public string TlsSignature { get; }
            public string ProxySignature { get; }

            public bool Equals(PoolKey other)
            {
                return Port == other.Port &&
                    UseTls == other.UseTls &&
                    string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(FingerprintSignature, other.FingerprintSignature, StringComparison.Ordinal) &&
                    string.Equals(TlsSignature, other.TlsSignature, StringComparison.Ordinal) &&
                    string.Equals(ProxySignature, other.ProxySignature, StringComparison.Ordinal);
            }

            public override bool Equals(object obj)
            {
                return obj is PoolKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                var hash = new HashCode();
                hash.Add(Host, StringComparer.OrdinalIgnoreCase);
                hash.Add(Port);
                hash.Add(UseTls);
                hash.Add(FingerprintSignature, StringComparer.Ordinal);
                hash.Add(TlsSignature, StringComparer.Ordinal);
                hash.Add(ProxySignature, StringComparer.Ordinal);
                return hash.ToHashCode();
            }
        }

        internal sealed class PoolState
        {
            private readonly ConcurrentQueue<TlsClient> _queue = new();
            private SemaphoreSlim _semaphore;
            private int _maxConnections;

            public ConcurrentQueue<TlsClient> Queue => _queue;

            public SemaphoreSlim GetSemaphore(int maxConnections)
            {
                if (_semaphore == null)
                {
                    lock (this)
                    {
                        _semaphore ??= new SemaphoreSlim(maxConnections, maxConnections);
                        _maxConnections = maxConnections;
                    }
                }
                else if (maxConnections > _maxConnections)
                {
                    lock (this)
                    {
                        if (maxConnections > _maxConnections)
                        {
                            var difference = maxConnections - _maxConnections;
                            _semaphore.Release(difference);
                            _maxConnections = maxConnections;
                        }
                    }
                }

                return _semaphore;
            }
        }
    }

    internal sealed class TlsClientLease : IDisposable
    {
        private readonly TlsConnectionPool _pool;
        private readonly TlsConnectionPool.PoolKey _key;
        private readonly TlsConnectionPool.PoolState _state;
        private readonly SemaphoreSlim _semaphore;
        private bool _disposed;
        private bool _canReuse;

        public TlsClientLease(
            TlsConnectionPool pool,
            TlsConnectionPool.PoolKey key,
            TlsConnectionPool.PoolState state,
            SemaphoreSlim semaphore,
            TlsClient client)
        {
            _pool = pool ?? throw new ArgumentNullException(nameof(pool));
            _key = key;
            _state = state ?? throw new ArgumentNullException(nameof(state));
            _semaphore = semaphore ?? throw new ArgumentNullException(nameof(semaphore));
            Client = client ?? throw new ArgumentNullException(nameof(client));
            _canReuse = false;
        }

        public TlsClient Client { get; }

        public void MarkReusable()
        {
            _canReuse = true;
        }

        public void MarkUnusable()
        {
            _canReuse = false;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _pool.Return(_key, _state, _semaphore, Client, _canReuse);
        }
    }
}
