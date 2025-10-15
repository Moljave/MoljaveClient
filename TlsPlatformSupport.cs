using System;

namespace Moljave.Http
{
    internal static class TlsPlatformSupport
    {
        private static readonly bool _supportsCipherSuitesPolicy = DetermineCipherSuitesPolicySupport();

        public static bool SupportsCipherSuitesPolicy() => _supportsCipherSuitesPolicy;

        private static bool DetermineCipherSuitesPolicySupport()
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
            {
                return false;
            }

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
