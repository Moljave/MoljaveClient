using System;
using System.Net;
using System.Net.Http;

namespace Moljave.Http
{
    /// <summary>
    /// Represents errors that occur while establishing or using a proxy connection.
    /// </summary>
    public sealed class ProxyException : HttpRequestException
    {
        public ProxyException(string message, ProxyErrorReason reason, HttpStatusCode? statusCode = null, Exception innerException = null)
            : base(message, innerException)
        {
            Reason = reason;
            StatusCode = statusCode;
        }

        public ProxyErrorReason Reason { get; }

        public HttpStatusCode? StatusCode { get; }
    }

    public enum ProxyErrorReason
    {
        ConnectionFailed,
        AuthenticationRequired,
        AuthenticationFailed,
        ResponseError,
        ProtocolError,
        Unsupported
    }
}
