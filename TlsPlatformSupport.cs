using System;

namespace Moljave.Http
{
    internal static class TlsPlatformSupport
    {
        private static readonly bool _supportsCipherSuitesPolicy = DetermineCipherSuitesPolicySupport();

        public static bool SupportsCipherSuitesPolicy() => _supportsCipherSuitesPolicy;

        private static bool DetermineCipherSuitesPolicySupport()
        {
#if NET6_0_OR_GREATER
            if (OperatingSystem.IsWindows())
            {
                return OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18362);
            }

            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD())
            {
                return true;
            }
#endif
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
    }
}
