using System;

namespace Moljave.Http
{
    internal static class TlsPlatformSupport
    {
        private static int _supportsCipherSuitesPolicy = DetermineCipherSuitesPolicySupport() ? 1 : 0;

        public static bool SupportsCipherSuitesPolicy() => System.Threading.Volatile.Read(ref _supportsCipherSuitesPolicy) == 1;

        public static bool TryDisableCipherSuitesPolicy(Exception exception)
        {
            if (System.Threading.Volatile.Read(ref _supportsCipherSuitesPolicy) == 0)
            {
                return false;
            }

            if (!ContainsPlatformNotSupported(exception))
            {
                return false;
            }

            return System.Threading.Interlocked.Exchange(ref _supportsCipherSuitesPolicy, 0) == 1;
        }

        private static bool DetermineCipherSuitesPolicySupport()
        {
            try
            {
                _ = new System.Net.Security.CipherSuitesPolicy(Array.Empty<System.Net.Security.TlsCipherSuite>());
                return true;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
        }

        private static bool ContainsPlatformNotSupported(Exception exception)
        {
            if (exception == null)
            {
                return false;
            }

            if (exception is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions)
                {
                    if (ContainsPlatformNotSupported(inner))
                    {
                        return true;
                    }
                }

                return false;
            }

            if (exception is PlatformNotSupportedException)
            {
                return true;
            }

            return ContainsPlatformNotSupported(exception.InnerException);
        }
    }
}
