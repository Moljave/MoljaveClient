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
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("MojaveHttpClient requires Windows.");
            }
        }
    }
}
