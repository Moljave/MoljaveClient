using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace Moljave.Http
{
    /// <summary>
    /// Provides round-robin style proxy rotation with basic cooldown support for failed proxies.
    /// </summary>
    public sealed class RotatingProxyProvider : IProxyRotationListener
    {
        private readonly MojaveProxyOptions[] _proxies;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _cooldowns;
        private int _cursor;

        /// <summary>
        /// Initializes a new instance of the <see cref="RotatingProxyProvider"/> class using raw proxy strings.
        /// </summary>
        /// <param name="proxies">A collection of proxy definitions compatible with <see cref="ProxyParser"/>.</param>
        /// <param name="failureCooldown">Optional cooldown duration applied after a proxy failure.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="proxies"/> is <c>null</c>.</exception>
        public RotatingProxyProvider(IEnumerable<string> proxies, TimeSpan? failureCooldown = null)
            : this(ParseRawProxies(proxies), failureCooldown)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RotatingProxyProvider"/> class using existing proxy options.
        /// </summary>
        /// <param name="proxies">A collection of <see cref="MojaveProxyOptions"/> instances.</param>
        /// <param name="failureCooldown">Optional cooldown duration applied after a proxy failure.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="proxies"/> is <c>null</c>.</exception>
        public RotatingProxyProvider(IEnumerable<MojaveProxyOptions> proxies, TimeSpan? failureCooldown = null)
        {
            if (proxies == null)
            {
                throw new ArgumentNullException(nameof(proxies));
            }

            var materialized = new List<MojaveProxyOptions>();
            foreach (var proxy in proxies)
            {
                if (proxy?.Descriptor == null)
                {
                    continue;
                }

                materialized.Add(MojaveProxyOptions.CreateWithListener(proxy.Descriptor, this));
            }

            _proxies = materialized.ToArray();
            _cooldowns = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
            _cursor = -1;

            FailureCooldown = failureCooldown ?? TimeSpan.FromSeconds(15);
        }

        /// <summary>
        /// Gets or sets the cooldown duration applied after a proxy failure. Set to <see cref="TimeSpan.Zero"/> to disable cooldowns.
        /// </summary>
        public TimeSpan FailureCooldown { get; set; }

        /// <summary>
        /// Gets a value indicating whether the provider has at least one configured proxy.
        /// </summary>
        public bool HasProxies => _proxies.Length > 0;

        /// <summary>
        /// Retrieves the next proxy in the rotation, skipping proxies that are in a cooldown period.
        /// </summary>
        /// <returns>The next <see cref="MojaveProxyOptions"/> to use, or <see cref="MojaveProxyOptions.NoProxy"/> if none are available.</returns>
        public MojaveProxyOptions GetNextProxy()
        {
            if (!HasProxies)
            {
                return MojaveProxyOptions.NoProxy;
            }

            var snapshot = _proxies;
            var now = DateTimeOffset.UtcNow;
            var start = (uint)Interlocked.Increment(ref _cursor);
            var baseIndex = (int)(start % (uint)snapshot.Length);

            for (var offset = 0; offset < snapshot.Length; offset++)
            {
                var proxy = snapshot[(baseIndex + offset) % snapshot.Length];
                if (proxy?.Descriptor == null)
                {
                    continue;
                }

                var key = BuildKey(proxy.Descriptor);
                if (_cooldowns.TryGetValue(key, out var until) && until > now)
                {
                    continue;
                }

                return proxy;
            }

            return MojaveProxyOptions.NoProxy;
        }

        void IProxyRotationListener.OnSuccess(MojaveProxyOptions options)
        {
            if (options?.Descriptor == null)
            {
                return;
            }

            var key = BuildKey(options.Descriptor);
            _cooldowns.TryRemove(key, out _);
        }

        void IProxyRotationListener.OnFailure(MojaveProxyOptions options, Exception exception)
        {
            if (options?.Descriptor == null)
            {
                return;
            }

            if (FailureCooldown <= TimeSpan.Zero)
            {
                return;
            }

            var key = BuildKey(options.Descriptor);
            var until = DateTimeOffset.UtcNow.Add(FailureCooldown);
            _cooldowns[key] = until;
        }

        private static IEnumerable<MojaveProxyOptions> ParseRawProxies(IEnumerable<string> proxies)
        {
            if (proxies == null)
            {
                throw new ArgumentNullException(nameof(proxies));
            }

            foreach (var entry in proxies)
            {
                if (string.IsNullOrWhiteSpace(entry))
                {
                    continue;
                }

                if (!ProxyParser.TryParse(entry, out var options) || options?.Descriptor == null)
                {
                    continue;
                }

                yield return options;
            }
        }

        private static string BuildKey(ProxyDescriptor descriptor)
        {
            if (descriptor == null)
            {
                return string.Empty;
            }

            var credential = descriptor.Credentials;
            var username = credential?.UserName ?? string.Empty;
            var password = credential?.Password ?? string.Empty;

            return string.Join("|", new[]
            {
                descriptor.Scheme.ToString(),
                descriptor.Host,
                descriptor.Port.ToString(),
                username,
                password,
                descriptor.ResolveHostnamesRemotely.ToString()
            });
        }
    }
}
