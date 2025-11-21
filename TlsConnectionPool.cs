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
        private readonly ConcurrentDictionary<ConnectionGateKey, ConnectionGate> _connectionGates = new();

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

            var poolKey = CreatePoolKey(
                host,
                port,
                useTls,
                fingerprint,
                tlsSettings,
                proxyDescriptor,
                affinityKey,
                socketBufferSize);

            var gateKey = CreateConnectionGateKey(host, port, useTls, proxyDescriptor);

            var state = _states.GetOrAdd(poolKey, _ => new PoolState());
            var gate = _connectionGates.GetOrAdd(gateKey, _ => new ConnectionGate(maxConnections));

            await gate.WaitAsync(maxConnections, cancellationToken).ConfigureAwait(false);

            try
            {
                while (state.Queue.TryDequeue(out var existing))
                {
                    if (existing != null && existing.IsReusable)
                    {
                        return new TlsClientLease(this, state, gate, existing);
                    }

                    existing?.Dispose();
                }

                var client = new TlsClient(
                    host,
                    port,
                    useTls,
                    fingerprint,
                    proxyDescriptor,
                    tlsSettings,
                    certificateValidationCallback,
                    socketBufferSize);

                return new TlsClientLease(this, state, gate, client);
            }
            catch
            {
                gate.ReleaseLease();
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

        public void ClearAffinity(object affinityKey, bool includeNullAffinity = false)
        {
            if (affinityKey == null && !includeNullAffinity)
            {
                return;
            }

            var affinityHash = affinityKey == null
                ? 0
                : RuntimeHelpers.GetHashCode(affinityKey);
            var keysToClear = new List<PoolKey>();

            foreach (var kvp in _states)
            {
                if (kvp.Key.AffinityHash == affinityHash)
                {
                    keysToClear.Add(kvp.Key);
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

            var gateKey = CreateConnectionGateKey(host, port, useTls, proxyDescriptor);
            if (_connectionGates.TryGetValue(gateKey, out var gate))
            {
                gate.AdjustMaxConnections(maxConnections);
            }
        }

        private static ConnectionGateKey CreateConnectionGateKey(
            string host,
            int port,
            bool useTls,
            ProxyDescriptor proxyDescriptor)
        {
            var effectiveHost = host;
            var effectivePort = port;
            var effectiveTls = useTls;

            if (proxyDescriptor != null)
            {
                effectiveHost = proxyDescriptor.Host;
                effectivePort = proxyDescriptor.Port;
                effectiveTls = proxyDescriptor.Scheme == ProxyScheme.Https;
            }

            return new ConnectionGateKey(effectiveHost, effectivePort, effectiveTls);
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
            ConnectionGate gate,
            TlsClient client,
            bool canReuse)
        {
            try
            {
                state.ReturnClient(client, canReuse);
            }
            finally
            {
                gate.ReleaseLease();
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

        internal readonly struct ConnectionGateKey : IEquatable<ConnectionGateKey>
        {
            public ConnectionGateKey(string host, int port, bool useTls)
            {
                Host = host;
                Port = port;
                UseTls = useTls;
            }

            public string Host { get; }
            public int Port { get; }
            public bool UseTls { get; }

            public bool Equals(ConnectionGateKey other)
            {
                return Port == other.Port &&
                    UseTls == other.UseTls &&
                    string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase);
            }

            public override bool Equals(object obj)
            {
                return obj is ConnectionGateKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                var hash = new HashCode();
                hash.Add(Host, StringComparer.OrdinalIgnoreCase);
                hash.Add(Port);
                hash.Add(UseTls);
                return hash.ToHashCode();
            }
        }

        internal sealed class ConnectionGate
        {
            private SemaphoreSlim _semaphore;
            private int _maxConnections;
            private int _reservedPermits;

            public ConnectionGate(int maxConnections)
            {
                maxConnections = Math.Max(1, maxConnections);
                _semaphore = new SemaphoreSlim(maxConnections, maxConnections);
                _maxConnections = maxConnections;
                _reservedPermits = 0;
            }

            public async Task WaitAsync(int maxConnections, CancellationToken cancellationToken)
            {
                var semaphore = GetSemaphore(maxConnections);
                await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            public void AdjustMaxConnections(int maxConnections)
            {
                maxConnections = Math.Max(1, maxConnections);

                lock (this)
                {
                    AdjustMaxConnectionsLocked(maxConnections);
                }
            }

            private SemaphoreSlim GetSemaphore(int maxConnections)
            {
                maxConnections = Math.Max(1, maxConnections);

                lock (this)
                {
                    AdjustMaxConnectionsLocked(maxConnections);
                    return _semaphore;
                }
            }

            private void AdjustMaxConnectionsLocked(int maxConnections)
            {
                if (maxConnections == _maxConnections)
                {
                    return;
                }

                if (maxConnections > _maxConnections)
                {
                    var inUse = (_maxConnections - _semaphore.CurrentCount) + _reservedPermits;
                    var available = Math.Max(0, maxConnections - inUse);

                    _semaphore = new SemaphoreSlim(available, maxConnections);
                    _reservedPermits = 0;
                    _maxConnections = maxConnections;
                    return;
                }

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

                _maxConnections = maxConnections;
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

        internal sealed class PoolState
        {
            private readonly ConcurrentQueue<TlsClient> _queue = new();

            public ConcurrentQueue<TlsClient> Queue => _queue;

            public void ClearQueue()
            {
                while (_queue.TryDequeue(out var client))
                {
                    client?.Dispose();
                }
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

        }
    }

    internal sealed class TlsClientLease : IDisposable
    {
        private readonly TlsConnectionPool _pool;
        private readonly TlsConnectionPool.PoolState _state;
        private readonly TlsConnectionPool.ConnectionGate _gate;
        private bool _disposed;
        private bool _canReuse;

        public TlsClientLease(
            TlsConnectionPool pool,
            TlsConnectionPool.PoolState state,
            TlsConnectionPool.ConnectionGate gate,
            TlsClient client)
        {
            _pool = pool ?? throw new ArgumentNullException(nameof(pool));
            _state = state ?? throw new ArgumentNullException(nameof(state));
            _gate = gate ?? throw new ArgumentNullException(nameof(gate));
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
            _pool.Return(_state, _gate, Client, _canReuse);
        }
    }
}
