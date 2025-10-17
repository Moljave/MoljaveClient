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

            var frameworkDescription = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
            if (string.IsNullOrWhiteSpace(frameworkDescription))
            {
                throw new PlatformNotSupportedException("Unable to determine the runtime version. MojaveHttpClient requires .NET 9.0.");
            }

            if (!frameworkDescription.Contains(".NET", StringComparison.OrdinalIgnoreCase))
            {
                throw new PlatformNotSupportedException($"Unsupported runtime '{frameworkDescription}'. MojaveHttpClient requires .NET 9.0 on Windows.");
            }

            var runtimeVersion = Environment.Version;
            if (runtimeVersion == null || runtimeVersion.Major < 9)
            {
                throw new PlatformNotSupportedException($"Detected runtime version '{frameworkDescription}'. MojaveHttpClient requires .NET 9.0 or later on Windows.");
            }
        }
    }
}
