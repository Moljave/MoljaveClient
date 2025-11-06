using System;
using System.Runtime.ExceptionServices;
using System.Threading;

namespace Moljave.Http
{
    internal static class PlatformRequirements
    {
        private static ExceptionDispatchInfo s_cachedException;
        private static int s_platformValidated;

        public static void EnsureSupportedWindows()
        {
            if (Volatile.Read(ref s_platformValidated) == 1)
            {
                s_cachedException?.Throw();
                return;
            }

            ExceptionDispatchInfo capturedException = null;

            try
            {
                ValidatePlatform();
            }
            catch (Exception ex)
            {
                capturedException = ExceptionDispatchInfo.Capture(ex);
            }

            Volatile.Write(ref s_cachedException, capturedException);
            Interlocked.Exchange(ref s_platformValidated, 1);

            capturedException?.Throw();
        }

        private static void ValidatePlatform()
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
