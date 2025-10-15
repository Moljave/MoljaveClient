using System;

namespace Moljave.Http
{
    internal sealed class ProxyRotationContext
    {
        private readonly bool _isFixed;
        private readonly Func<MojaveProxyOptions> _resolver;
        private readonly object _lock = new();
        private MojaveProxyOptions _cachedProxy;
        private bool _needsRefresh;

        private ProxyRotationContext(MojaveProxyOptions proxyOverride)
        {
            _isFixed = true;
            _resolver = null;
            _cachedProxy = Normalize(proxyOverride);
            _needsRefresh = false;
        }

        private ProxyRotationContext(Func<MojaveProxyOptions> resolver)
        {
            _isFixed = false;
            _resolver = resolver ?? (() => MojaveProxyOptions.NoProxy);
            _needsRefresh = true;
        }

        public static ProxyRotationContext FromOverride(MojaveProxyOptions proxyOverride)
            => new(proxyOverride);

        public static ProxyRotationContext FromResolver(Func<MojaveProxyOptions> resolver)
            => new(resolver);

        public MojaveProxyOptions GetProxyForAttempt(int attempt)
        {
            if (_isFixed)
            {
                return _cachedProxy;
            }

            lock (_lock)
            {
                if (_needsRefresh || _cachedProxy == null)
                {
                    _cachedProxy = Resolve();
                    _needsRefresh = false;
                }

                return _cachedProxy;
            }
        }

        public void NotifyFailure(MojaveProxyOptions proxy, Exception exception)
        {
            if (!_isFixed)
            {
                lock (_lock)
                {
                    _needsRefresh = true;
                }
            }

            proxy?.RotationListener?.OnFailure(proxy, exception);
        }

        public void NotifySuccess(MojaveProxyOptions proxy)
        {
            proxy?.RotationListener?.OnSuccess(proxy);
        }

        private MojaveProxyOptions Resolve()
        {
            try
            {
                return Normalize(_resolver());
            }
            catch (Exception ex)
            {
                throw new ProxyException(
                    "The proxy resolver threw an exception.",
                    ProxyErrorReason.Unsupported,
                    innerException: ex);
            }
        }

        private static MojaveProxyOptions Normalize(MojaveProxyOptions options)
            => options ?? MojaveProxyOptions.NoProxy;
    }
}
