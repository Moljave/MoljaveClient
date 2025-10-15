using System;

namespace Moljave.Http
{
    internal static class PlatformRequirements
    {
        public static void EnsureSupportedWindows()
        {
            const int minimumBuild = 19041; // Windows 10 version 2004

            if (!OperatingSystem.IsWindows() || !OperatingSystem.IsWindowsVersionAtLeast(10, 0, minimumBuild))
            {
                throw new PlatformNotSupportedException("MojaveHttpClient requires Windows 10 version 2004 (build 19041) or newer.");
            }
        }
    }
}
