using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Runtime.CompilerServices;
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
            object affinityKey,
            RemoteCertificateValidationCallback certificateValidationCallback,
            int maxConnections,
            int socketBufferSize,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(host))
            {
                throw new ArgumentNullException(nameof(host));
            }

            maxConnections = Math.Max(1, maxConnections);

            var key = CreatePoolKey(
                host,
                port,
                useTls,
                fingerprint,
                tlsSettings,
                proxyDescriptor,
                affinityKey,
                socketBufferSize);

            var state = _states.GetOrAdd(key, _ => new PoolState());
            var semaphore = state.GetSemaphore(maxConnections);

            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                while (state.Queue.TryDequeue(out var existing))
                {
                    if (existing != null && existing.IsReusable)
                    {
                        return new TlsClientLease(this, state, existing);
                    }

                    existing?.Dispose();
                }

                var client = new TlsClient(
                    host,
                    port,
                    fingerprint,
                    proxyDescriptor,
                    tlsSettings,
                    certificateValidationCallback,
                    socketBufferSize);

                return new TlsClientLease(this, state, client);
            }
            catch
            {
                state.ReleaseLease();
                throw;
            }
        }

        public void Clear(
            string host,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            ProxyDescriptor proxyDescriptor,
            object affinityKey,
            int socketBufferSize)
        {
            if (string.IsNullOrEmpty(host))
            {
                return;
            }

            var key = CreatePoolKey(
                host,
                port,
                useTls,
                fingerprint,
                tlsSettings,
                proxyDescriptor,
                affinityKey,
                socketBufferSize);

            if (_states.TryGetValue(key, out var state))
            {
                state.ClearQueue();
            }
        }

        public void ClearHostVariants(string host, int port, bool useTls)
        {
            if (string.IsNullOrEmpty(host))
            {
                return;
            }

            var keysToClear = new List<PoolKey>();

            foreach (var kvp in _states)
            {
                var key = kvp.Key;
                if (key.Port == port &&
                    key.UseTls == useTls &&
                    string.Equals(key.Host, host, StringComparison.OrdinalIgnoreCase))
                {
                    keysToClear.Add(key);
                }
            }

            foreach (var key in keysToClear)
            {
                if (_states.TryRemove(key, out var state))
                {
                    state.ClearQueue();
                }
                else if (_states.TryGetValue(key, out var existing))
                {
                    existing.ClearQueue();
                }
            }
        }

        public void AdjustMaxConnections(
            string host,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            ProxyDescriptor proxyDescriptor,
            object affinityKey,
            int socketBufferSize,
            int maxConnections)
        {
            if (string.IsNullOrEmpty(host))
            {
                return;
            }

            var key = CreatePoolKey(
                host,
                port,
                useTls,
                fingerprint,
                tlsSettings,
                proxyDescriptor,
                affinityKey,
                socketBufferSize);

            if (_states.TryGetValue(key, out var state))
            {
                state.AdjustMaxConnections(maxConnections);
            }
        }

        private static PoolKey CreatePoolKey(
            string host,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            ProxyDescriptor proxyDescriptor,
            object affinityKey,
            int socketBufferSize)
        {
            var affinityHash = affinityKey == null
                ? 0
                : RuntimeHelpers.GetHashCode(affinityKey);

            return new PoolKey(
                host,
                port,
                useTls,
                BuildFingerprintSignature(fingerprint),
                BuildTlsSignature(tlsSettings),
                BuildProxySignature(proxyDescriptor),
                affinityHash,
                socketBufferSize);
        }

        internal void Return(
            PoolState state,
            TlsClient client,
            bool canReuse)
        {
            try
            {
                state.ReturnClient(client, canReuse);
            }
            finally
            {
                state.ReleaseLease();
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
            public PoolKey(string host, int port, bool useTls, string fingerprintSignature, string tlsSignature, string proxySignature, int affinityHash, int socketBufferSize)
            {
                Host = host;
                Port = port;
                UseTls = useTls;
                FingerprintSignature = fingerprintSignature;
                TlsSignature = tlsSignature;
                ProxySignature = proxySignature;
                AffinityHash = affinityHash;
                SocketBufferSize = socketBufferSize;
            }

            public string Host { get; }
            public int Port { get; }
            public bool UseTls { get; }
            public string FingerprintSignature { get; }
            public string TlsSignature { get; }
            public string ProxySignature { get; }
            public int AffinityHash { get; }
            public int SocketBufferSize { get; }

            public bool Equals(PoolKey other)
            {
                return Port == other.Port &&
                    UseTls == other.UseTls &&
                    string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(FingerprintSignature, other.FingerprintSignature, StringComparison.Ordinal) &&
                    string.Equals(TlsSignature, other.TlsSignature, StringComparison.Ordinal) &&
                    string.Equals(ProxySignature, other.ProxySignature, StringComparison.Ordinal) &&
                    AffinityHash == other.AffinityHash &&
                    SocketBufferSize == other.SocketBufferSize;
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
                hash.Add(AffinityHash);
                hash.Add(SocketBufferSize);
                return hash.ToHashCode();
            }
        }

        internal sealed class PoolState
        {
            private readonly ConcurrentQueue<TlsClient> _queue = new();
            private SemaphoreSlim _semaphore;
            private int _maxConnections;
            private int _reservedPermits;

            public ConcurrentQueue<TlsClient> Queue => _queue;

            public SemaphoreSlim GetSemaphore(int maxConnections)
            {
                maxConnections = Math.Max(1, maxConnections);

                lock (this)
                {
                    if (_semaphore == null)
                    {
                        _semaphore = new SemaphoreSlim(maxConnections, maxConnections);
                        _maxConnections = maxConnections;
                        _reservedPermits = 0;
                        return _semaphore;
                    }

                    AdjustMaxConnectionsLocked(maxConnections);
                    return _semaphore;
                }
            }

            public void ClearQueue()
            {
                while (_queue.TryDequeue(out var client))
                {
                    client?.Dispose();
                }
            }

            public void AdjustMaxConnections(int maxConnections)
            {
                if (_semaphore == null)
                {
                    return;
                }

                maxConnections = Math.Max(1, maxConnections);

                lock (this)
                {
                    AdjustMaxConnectionsLocked(maxConnections);
                }
            }

            private void AdjustMaxConnectionsLocked(int maxConnections)
            {
                if (_semaphore == null)
                {
                    return;
                }

                if (maxConnections == _maxConnections)
                {
                    return;
                }

                if (maxConnections > _maxConnections)
                {
                    var difference = maxConnections - _maxConnections;

                    if (_reservedPermits > 0)
                    {
                        var restore = Math.Min(_reservedPermits, difference);
                        _reservedPermits -= restore;
                        difference -= restore;
                    }

                    if (difference > 0)
                    {
                        _semaphore.Release(difference);
                    }
                }
                else
                {
                    var difference = _maxConnections - maxConnections;
                    var drained = 0;
                    for (; drained < difference; drained++)
                    {
                        if (!_semaphore.Wait(0))
                        {
                            break;
                        }
                    }

                    var remaining = difference - drained;
                    if (remaining > 0)
                    {
                        _reservedPermits += remaining;
                    }
                }

                _maxConnections = maxConnections;
            }

            public void ReturnClient(TlsClient client, bool canReuse)
            {
                if (canReuse && client != null && client.IsReusable)
                {
                    _queue.Enqueue(client);
                }
                else
                {
                    client?.Dispose();
                }
            }

            public void ReleaseLease()
            {
                var semaphore = _semaphore;
                if (semaphore == null)
                {
                    return;
                }

                lock (this)
                {
                    if (_reservedPermits > 0)
                    {
                        _reservedPermits--;
                        return;
                    }
                }

                semaphore.Release();
            }
        }
    }

    internal sealed class TlsClientLease : IDisposable
    {
        private readonly TlsConnectionPool _pool;
        private readonly TlsConnectionPool.PoolState _state;
        private bool _disposed;
        private bool _canReuse;

        public TlsClientLease(
            TlsConnectionPool pool,
            TlsConnectionPool.PoolState state,
            TlsClient client)
        {
            _pool = pool ?? throw new ArgumentNullException(nameof(pool));
            _state = state ?? throw new ArgumentNullException(nameof(state));
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
            _pool.Return(_state, Client, _canReuse);
        }
    }
}
