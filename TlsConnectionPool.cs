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
        private static readonly Timer _cleanupTimer;
        private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan ConnectionIdleTimeout = TimeSpan.FromSeconds(10);

        private readonly ConcurrentDictionary<PoolKey, PoolState> _states = new();

        public static TlsConnectionPool Shared { get; } = new TlsConnectionPool();

        static TlsConnectionPool()
        {
            _cleanupTimer = new Timer(Cleanup, null, CleanupInterval, CleanupInterval);
        }

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
                while (state.TryTakeClient(out var pooledClient))
                {
                    if (pooledClient != null && pooledClient.IsReusable)
                    {
                        return new TlsClientLease(this, state, pooledClient);
                    }

                    pooledClient?.Dispose();
                }

                var newClient = new TlsClient(
                    host,
                    port,
                    fingerprint,
                    proxyDescriptor,
                    tlsSettings,
                    certificateValidationCallback,
                    socketBufferSize);

                return new TlsClientLease(this, state, newClient);
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

        public void ClearConnectionsForSession(object affinityKey)
        {
            if (affinityKey == null)
            {
                return;
            }

            foreach (var kvp in _states)
            {
                var key = kvp.Key;
                if (!ReferenceEquals(key.AffinityKey, affinityKey))
                {
                    continue;
                }

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

        private static PoolKey CreatePoolKey(
            string host,
            int port,
            bool useTls,
            JA3Fingerprint fingerprint,
            MojaveTlsSettings tlsSettings,
            ProxyDescriptor proxyDescriptor,
            object affinityKey,
            int socketBufferSize)
            => new PoolKey(
                host,
                port,
                useTls,
                fingerprint,
                tlsSettings,
                proxyDescriptor,
                affinityKey,
                socketBufferSize);

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

        internal readonly struct PoolKey : IEquatable<PoolKey>
        {
            public PoolKey(
                string host,
                int port,
                bool useTls,
                JA3Fingerprint fingerprint,
                MojaveTlsSettings tlsSettings,
                ProxyDescriptor proxyDescriptor,
                object affinityKey,
                int socketBufferSize)
            {
                Host = host;
                Port = port;
                UseTls = useTls;
                Fingerprint = fingerprint;
                TlsSettings = tlsSettings;
                ProxyDescriptor = proxyDescriptor;
                AffinityKey = affinityKey;
                SocketBufferSize = socketBufferSize;
            }

            public string Host { get; }
            public int Port { get; }
            public bool UseTls { get; }
            public JA3Fingerprint Fingerprint { get; }
            public MojaveTlsSettings TlsSettings { get; }
            public ProxyDescriptor ProxyDescriptor { get; }
            public object AffinityKey { get; }
            public int SocketBufferSize { get; }

            public bool Equals(PoolKey other)
            {
                return Port == other.Port &&
                       UseTls == other.UseTls &&
                       SocketBufferSize == other.SocketBufferSize &&
                       string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase) &&
                       Equals(Fingerprint, other.Fingerprint) &&
                       Equals(TlsSettings, other.TlsSettings) &&
                       Equals(ProxyDescriptor, other.ProxyDescriptor) &&
                       ReferenceEquals(AffinityKey, other.AffinityKey);
            }

            public override bool Equals(object obj) => obj is PoolKey other && Equals(other);

            public override int GetHashCode()
            {
                var hash = new HashCode();
                hash.Add(Host, StringComparer.OrdinalIgnoreCase);
                hash.Add(Port);
                hash.Add(UseTls);
                hash.Add(Fingerprint);
                hash.Add(TlsSettings);
                hash.Add(ProxyDescriptor);
                hash.Add(AffinityKey != null ? RuntimeHelpers.GetHashCode(AffinityKey) : 0);
                hash.Add(SocketBufferSize);
                return hash.ToHashCode();
            }
        }

        private static void Cleanup(object state)
        {
            Shared.CleanupExpiredConnections();
        }

        private void CleanupExpiredConnections()
        {
            var now = DateTime.UtcNow;

            foreach (var state in _states.Values)
            {
                state.CleanupStaleConnections(now, ConnectionIdleTimeout);
            }
        }

        private readonly struct PooledConnection
        {
            public PooledConnection(TlsClient client, DateTime lastUsed)
            {
                Client = client;
                LastUsedTimestamp = lastUsed;
            }

            public TlsClient Client { get; }
            public DateTime LastUsedTimestamp { get; }
        }

        internal sealed class PoolState
        {
            private readonly ConcurrentQueue<PooledConnection> _queue = new();
            private SemaphoreSlim _semaphore;
            private int _maxConnections;
            private int _reservedPermits;

            public bool TryTakeClient(out TlsClient client)
            {
                while (_queue.TryDequeue(out var connection))
                {
                    client = connection.Client;
                    return true;
                }

                client = null;
                return false;
            }

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
                while (_queue.TryDequeue(out var connection))
                {
                    connection.Client?.Dispose();
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
                    _queue.Enqueue(new PooledConnection(client, DateTime.UtcNow));
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

            public void CleanupStaleConnections(DateTime utcNow, TimeSpan idleTimeout)
            {
                if (_queue.IsEmpty)
                {
                    return;
                }

                var iterations = _queue.Count;
                for (int i = 0; i < iterations; i++)
                {
                    if (!_queue.TryDequeue(out var connection))
                    {
                        break;
                    }

                    var client = connection.Client;
                    if (client == null)
                    {
                        continue;
                    }

                    var idleDuration = utcNow - connection.LastUsedTimestamp;
                    if (idleDuration <= idleTimeout && client.IsReusable)
                    {
                        _queue.Enqueue(connection);
                    }
                    else
                    {
                        try
                        {
                            client.Dispose();
                        }
                        catch
                        {
                        }
                    }
                }
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
