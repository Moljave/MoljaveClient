using System;

namespace Moljave.Http
{
    internal interface IProxyRotationListener
    {
        void OnSuccess(MojaveProxyOptions options);
        void OnFailure(MojaveProxyOptions options, Exception exception);
    }
}
