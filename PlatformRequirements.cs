using System;

namespace Moljave.Http
{
    internal static class PlatformRequirements
    {
        public static void EnsureWindows11()
        {
            if (!OperatingSystem.IsWindows() || !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
            {
                throw new PlatformNotSupportedException("MojaveHttpClient supports only Windows 11 or later.");
            }
        }
    }
}
