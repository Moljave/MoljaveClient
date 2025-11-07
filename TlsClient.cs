using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Moljave.Http
{
    public sealed class TlsClient : IDisposable
    {
        private static readonly IdnMapping s_idnMapping = new();
        private static readonly byte[] s_socks4DomainPlaceholder = { 0x00, 0x00, 0x00, 0x01 };
        private static readonly byte[] s_socks5GreetingNoAuth = { 0x05, 0x01, 0x00 };
        private static readonly byte[] s_socks5GreetingWithAuth = { 0x05, 0x02, 0x00, 0x02 };

        private const int MinimumSocketBufferSize = 1024;

        private readonly string _host;
        private readonly int _port;
        private readonly JA3Fingerprint _fingerprint;
        private readonly ProxyDescriptor _proxy;
        private readonly MojaveTlsSettings _tlsSettings;
        private readonly RemoteCertificateValidationCallback _certificateValidationCallback;
        private int _socketBufferSize;

        private TcpClient _tcpClient;
        private Stream _transportStream;
        private SslStream _sslStream;
        private bool _disposed;

        public TlsClient(
            string host,
            int port,
            JA3Fingerprint fingerprint,
            ProxyDescriptor proxy,
            MojaveTlsSettings tlsSettings,
            RemoteCertificateValidationCallback certificateValidationCallback,
            int socketBufferSize)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _fingerprint = fingerprint;
            _proxy = proxy;
            _tlsSettings = tlsSettings ?? MojaveTlsSettings.Default;
            _certificateValidationCallback = certificateValidationCallback ?? ((_, _, _, _) => true);
            if (socketBufferSize <= 0)
            {
                _socketBufferSize = 0;
            }
            else
            {
                var sanitized = Math.Max(socketBufferSize, MinimumSocketBufferSize);
                _socketBufferSize = sanitized;
            }
        }

        public async Task<HttpResponseMessage> SendRequestAsync(ReadOnlyMemory<byte> requestBuffer, CancellationToken cancellationToken, bool useTls)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(TlsClient));
            }

            var activeStream = await GetActiveStreamAsync(useTls, cancellationToken).ConfigureAwait(false);

            if (!requestBuffer.IsEmpty)
            {
                await activeStream.WriteAsync(requestBuffer, cancellationToken).ConfigureAwait(false);
            }
            await activeStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var headerResult = await ReadHeadersAsync(activeStream, cancellationToken).ConfigureAwait(false);
            try
            {
                var headerSpan = headerResult.HeaderBuffer.AsSpan(0, headerResult.HeaderLength);
                ParseBodyMetadata(headerSpan,
                    out bool hasContentLength,
                    out int contentLength,
                    out bool isChunked);

                using var responseStream = new BufferedReadStream(activeStream, headerResult.PrefetchBuffer, headerResult.PrefetchLength);
                var bodyWriter = new ArrayBufferWriter<byte>(GetInitialBodyBufferSize(hasContentLength ? contentLength : -1));

                if (isChunked)
                {
                    await ReadChunkedBodyAsync(responseStream, bodyWriter, cancellationToken).ConfigureAwait(false);
                }
                else if (hasContentLength)
                {
                    await ReadFixedBodyAsync(responseStream, bodyWriter, contentLength, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await ReadUntilEndAsync(responseStream, bodyWriter, cancellationToken).ConfigureAwait(false);
                }

                return HttpResponseParser.Parse(headerSpan, bodyWriter.WrittenMemory);
            }
            finally
            {
                if (headerResult.PrefetchBuffer.Length > 0)
                {
                    ArrayPool<byte>.Shared.Return(headerResult.PrefetchBuffer);
                }

                ArrayPool<byte>.Shared.Return(headerResult.HeaderBuffer);
            }
        }

        public async Task<Stream> CreateTransportStreamAsync(CancellationToken cancellationToken)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(TlsClient));
            }

            if (_transportStream != null)
            {
                return _transportStream;
            }

            while (true)
            {
                var tcpClient = new TcpClient
                {
                    NoDelay = true,
                    // Use an abortive close so sockets do not pile up in TIME_WAIT when running at high volume.
                    LingerState = new LingerOption(enable: true, seconds: 0)
                };

                TryConfigureSocketBuffers(tcpClient, _socketBufferSize);
                ConfigureForHighVolumeReuse(tcpClient);

                _tcpClient = tcpClient;

                try
                {
                    if (_proxy == null)
                    {
                        var targetHost = NormalizeHostname(_host);
                        await tcpClient.ConnectAsync(targetHost, _port).WaitAsync(cancellationToken).ConfigureAwait(false);
                        _transportStream = tcpClient.GetStream();
                    }
                    else
                    {
                        await ConnectThroughProxyAsync(cancellationToken).ConfigureAwait(false);
                    }

                    return _transportStream;
                }
                catch (Exception ex) when (IsNoBufferSpaceAvailable(ex) && TryReduceSocketBufferSize())
                {
                    CleanupFailedConnection();
                    continue;
                }
                catch
                {
                    CleanupFailedConnection();
                    throw;
                }
            }
        }

        private async Task<Stream> GetActiveStreamAsync(bool useTls, CancellationToken cancellationToken)
        {
            var transportStream = await CreateTransportStreamAsync(cancellationToken).ConfigureAwait(false);

            if (!useTls)
            {
                return transportStream;
            }

            if (_sslStream != null)
            {
                return _sslStream;
            }

            _sslStream = new SslStream(transportStream, leaveInnerStreamOpen: false, GetValidationCallback());
            var authenticationOptions = BuildAuthenticationOptions(_host);
            await _sslStream.AuthenticateAsClientAsync(authenticationOptions, cancellationToken).ConfigureAwait(false);
            return _sslStream;
        }

        public bool IsReusable
        {
            get
            {
                if (_disposed)
                {
                    return false;
                }

                var client = _tcpClient;
                if (client == null)
                {
                    return false;
                }

                try
                {
                    var socket = client.Client;
                    if (socket == null || !socket.Connected)
                    {
                        return false;
                    }

                    if (socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0)
                    {
                        return false;
                    }

                    return true;
                }
                catch (ObjectDisposedException)
                {
                    return false;
                }
            }
        }

        private static void ConfigureForHighVolumeReuse(TcpClient client)
        {
            if (client == null)
            {
                return;
            }

            try
            {
                client.ExclusiveAddressUse = false;
            }
            catch (SocketException)
            {
                // Some environments do not allow toggling exclusive address use on TCP clients.
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (PlatformNotSupportedException)
            {
                // Ignore when the platform does not expose the option.
            }

            var socket = client.Client;
            if (socket == null)
            {
                return;
            }

            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, optionValue: true);
            }
            catch (SocketException)
            {
                // Ignore when the platform forbids enabling address reuse.
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseUnicastPort, optionValue: true);
            }
            catch (SocketException)
            {
                // Older Windows builds may not allow configuring unicast port reuse.
            }
            catch (PlatformNotSupportedException)
            {
            }
            catch (NotSupportedException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private static void TryConfigureSocketBuffers(TcpClient client, int size)
        {
            if (client == null || size <= 0)
            {
                return;
            }

            try
            {
                client.ReceiveBufferSize = size;
                client.SendBufferSize = size;
            }
            catch (SocketException)
            {
                // Ignore failures when the platform does not allow overriding buffer sizes.
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            var socket = client.Client;
            if (socket == null)
            {
                return;
            }

            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, size);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, size);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private static bool IsNoBufferSpaceAvailable(Exception exception)
        {
            if (exception == null)
            {
                return false;
            }

            var current = exception;
            while (current != null)
            {
                if (current is SocketException socketException &&
                    socketException.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                {
                    return true;
                }

                current = current.InnerException;
            }

            return false;
        }

        private bool TryReduceSocketBufferSize()
        {
            if (_socketBufferSize <= 0)
            {
                return false;
            }

            if (_socketBufferSize <= MinimumSocketBufferSize)
            {
                _socketBufferSize = 0;
                return true;
            }

            var reduced = Math.Max(MinimumSocketBufferSize, _socketBufferSize / 2);
            if (reduced == _socketBufferSize)
            {
                reduced = MinimumSocketBufferSize;
            }

            _socketBufferSize = reduced;
            return true;
        }

        private void CleanupFailedConnection()
        {
            _sslStream?.Dispose();
            _transportStream?.Dispose();
            _tcpClient?.Dispose();

            _sslStream = null;
            _transportStream = null;
            _tcpClient = null;
        }

        private async Task ConnectThroughProxyAsync(CancellationToken cancellationToken)
        {
            var proxyHost = _proxy.Host;
            var proxyPort = _proxy.Port;

            try
            {
                await _tcpClient.ConnectAsync(proxyHost, proxyPort).WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or IOException)
            {
                throw new ProxyException($"Failed to connect to proxy {proxyHost}:{proxyPort}.", ProxyErrorReason.ConnectionFailed, innerException: ex);
            }

            var networkStream = _tcpClient.GetStream();
            Stream activeStream = networkStream;

            try
            {
                if (_proxy.Scheme == ProxyScheme.Https)
                {
                    activeStream = await WrapProxyConnectionInTlsAsync(activeStream, cancellationToken).ConfigureAwait(false);
                }

                switch (_proxy.Scheme)
                {
                    case ProxyScheme.Http:
                    case ProxyScheme.Https:
                        _transportStream = await EstablishHttpTunnelAsync(activeStream, cancellationToken).ConfigureAwait(false);
                        break;
                    case ProxyScheme.Socks4:
                    case ProxyScheme.Socks4a:
                        _transportStream = await EstablishSocks4TunnelAsync(networkStream, cancellationToken).ConfigureAwait(false);
                        break;
                    case ProxyScheme.Socks5:
                        _transportStream = await EstablishSocks5TunnelAsync(networkStream, cancellationToken).ConfigureAwait(false);
                        break;
                    default:
                        throw new ProxyException($"Proxy scheme {_proxy.Scheme} is not supported.", ProxyErrorReason.Unsupported);
                }
            }
            catch (ProxyException)
            {
                throw;
            }
            catch (AuthenticationException ex)
            {
                throw new ProxyException("Proxy TLS negotiation failed.", ProxyErrorReason.AuthenticationFailed, innerException: ex);
            }
            catch (Exception ex) when (ex is IOException or SocketException)
            {
                throw new ProxyException("Proxy negotiation failed.", ProxyErrorReason.ProtocolError, innerException: ex);
            }
        }

        private async Task<Stream> EstablishHttpTunnelAsync(Stream stream, CancellationToken cancellationToken)
        {
            var authority = GetProxyAuthority();
            var builder = new StringBuilder();
            builder.Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n");
            builder.Append("Host: ").Append(authority).Append("\r\n");
            builder.Append("Proxy-Connection: Keep-Alive\r\n");
            builder.Append("Connection: Keep-Alive\r\n");
            builder.Append("Pragma: no-cache\r\n");

            if (_proxy.Credentials is NetworkCredential creds)
            {
                var authHeader = BuildProxyAuthorizationHeader(creds);
                if (!string.IsNullOrEmpty(authHeader))
                {
                    builder.Append("Proxy-Authorization: ").Append(authHeader).Append("\r\n");
                }
            }

            builder.Append("\r\n");

            var requestBytes = Encoding.ASCII.GetBytes(builder.ToString());
            await stream.WriteAsync(requestBytes, 0, requestBytes.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var response = await ReadHttpProxyResponseAsync(stream, cancellationToken).ConfigureAwait(false);
            if (!IsSuccessfulHttpProxyResponse(response.Text, out var statusCode, out var statusLine))
            {
                var reason = statusCode == HttpStatusCode.ProxyAuthenticationRequired
                    ? ProxyErrorReason.AuthenticationRequired
                    : ProxyErrorReason.ResponseError;
                var message = statusLine != null
                    ? $"Proxy CONNECT failed: {statusLine}"
                    : "Proxy CONNECT failed with an invalid response.";
                throw new ProxyException(message, reason, statusCode);
            }

            if (response.PrefetchLength <= 0)
            {
                return stream;
            }

            return new PrefixedStream(stream, response.PrefetchBuffer, response.PrefetchLength);
        }

        private static async Task<ProxyResponseBuffer> ReadHttpProxyResponseAsync(Stream stream, CancellationToken cancellationToken)
        {
            var headerResult = await ReadHeadersAsync(stream, cancellationToken).ConfigureAwait(false);
            var text = Encoding.ASCII.GetString(headerResult.HeaderBuffer, 0, headerResult.HeaderLength);
            return new ProxyResponseBuffer(text, headerResult.PrefetchBuffer, headerResult.PrefetchLength);
        }

        private async Task<Stream> WrapProxyConnectionInTlsAsync(Stream stream, CancellationToken cancellationToken)
        {
            var sslStream = new SslStream(stream, leaveInnerStreamOpen: false, GetProxyValidationCallback());

            try
            {
                var options = BuildAuthenticationOptions(_proxy.Host);
                await sslStream.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);
                return sslStream;
            }
            catch
            {
                sslStream.Dispose();
                throw;
            }
        }

        private async Task<Stream> EstablishSocks4TunnelAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var normalizedHost = NormalizeHostname(_host);
            var addressBytes = !_proxy.ResolveHostnamesRemotely && TryGetIpAddress(normalizedHost, out var ipAddress)
                ? ipAddress.GetAddressBytes()
                : s_socks4DomainPlaceholder;

            var userId = _proxy.Credentials?.UserName ?? string.Empty;
            var hostBytes = Encoding.ASCII.GetBytes(normalizedHost ?? string.Empty);

            bool useDomain = addressBytes[0] == 0x00 && addressBytes[1] == 0x00 && addressBytes[2] == 0x00 && addressBytes[3] == 0x01;
            if (useDomain && hostBytes.Length > byte.MaxValue)
            {
                throw new ProxyException("SOCKS4 proxy hostname is too long.", ProxyErrorReason.Unsupported);
            }

            byte[] buffer = null;
            byte[] response = null;

            try
            {
                var bufferLength = 9 + userId.Length + (useDomain ? hostBytes.Length + 1 : 0);
                buffer = ArrayPool<byte>.Shared.Rent(bufferLength);
                int index = 0;
                buffer[index++] = 0x04;
                buffer[index++] = 0x01;
                buffer[index++] = (byte)(_port >> 8);
                buffer[index++] = (byte)(_port & 0xFF);
                Buffer.BlockCopy(addressBytes, 0, buffer, index, 4);
                index += 4;
                var userBytes = Encoding.ASCII.GetBytes(userId);
                Buffer.BlockCopy(userBytes, 0, buffer, index, userBytes.Length);
                index += userBytes.Length;
                buffer[index++] = 0x00;

                if (useDomain)
                {
                    Buffer.BlockCopy(hostBytes, 0, buffer, index, hostBytes.Length);
                    index += hostBytes.Length;
                    buffer[index++] = 0x00;
                }

                await stream.WriteAsync(buffer, 0, index, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

                response = ArrayPool<byte>.Shared.Rent(8);
                await ReadExactAsync(stream, response, 8, cancellationToken).ConfigureAwait(false);

                if (response[1] != 0x5A)
                {
                    throw new ProxyException($"SOCKS4 proxy connection failed: {DescribeSocks4Status(response[1])}", ProxyErrorReason.ResponseError);
                }

                return stream;
            }
            finally
            {
                if (buffer != null)
                {
                    ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                }

                if (response != null)
                {
                    ArrayPool<byte>.Shared.Return(response);
                }
            }
        }

        private async Task<Stream> EstablishSocks5TunnelAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var hasCredentials = _proxy.Credentials is NetworkCredential;
            var greeting = hasCredentials ? s_socks5GreetingWithAuth : s_socks5GreetingNoAuth;

            await stream.WriteAsync(greeting, 0, greeting.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            byte[] methodSelection = null;
            byte[] authRequest = null;
            byte[] authResponse = null;
            byte[] connectRequest = null;
            byte[] responseHeader = null;
            byte[] skipBuffer = null;

            try
            {
                methodSelection = ArrayPool<byte>.Shared.Rent(2);
                await ReadExactAsync(stream, methodSelection, 2, cancellationToken).ConfigureAwait(false);

                if (methodSelection[0] != 0x05)
                {
                    throw new ProxyException("SOCKS5 proxy handshake failed: invalid version.", ProxyErrorReason.ProtocolError);
                }

                if (methodSelection[1] == 0x02)
                {
                    if (!hasCredentials)
                    {
                        throw new ProxyException("SOCKS5 proxy requires authentication but no credentials were provided.", ProxyErrorReason.AuthenticationRequired);
                    }

                    var creds = (NetworkCredential)_proxy.Credentials;
                    var userBytes = Encoding.ASCII.GetBytes(creds.UserName ?? string.Empty);
                    var passBytes = Encoding.ASCII.GetBytes(creds.Password ?? string.Empty);
                    var authLength = 3 + userBytes.Length + passBytes.Length;
                    authRequest = ArrayPool<byte>.Shared.Rent(authLength);
                    int index = 0;
                    authRequest[index++] = 0x01;
                    authRequest[index++] = (byte)userBytes.Length;
                    Buffer.BlockCopy(userBytes, 0, authRequest, index, userBytes.Length);
                    index += userBytes.Length;
                    authRequest[index++] = (byte)passBytes.Length;
                    Buffer.BlockCopy(passBytes, 0, authRequest, index, passBytes.Length);

                    await stream.WriteAsync(authRequest, 0, authLength, cancellationToken).ConfigureAwait(false);
                    await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

                    authResponse = ArrayPool<byte>.Shared.Rent(2);
                    await ReadExactAsync(stream, authResponse, 2, cancellationToken).ConfigureAwait(false);
                    if (authResponse[1] != 0x00)
                    {
                        throw new ProxyException("SOCKS5 proxy authentication failed.", ProxyErrorReason.AuthenticationFailed);
                    }
                }
                else if (methodSelection[1] == 0xFF)
                {
                    throw new ProxyException("SOCKS5 proxy does not accept provided authentication methods.", ProxyErrorReason.AuthenticationFailed);
                }
                else if (methodSelection[1] != 0x00)
                {
                    throw new ProxyException(
                        $"SOCKS5 proxy returned unsupported authentication method 0x{methodSelection[1]:X2}.",
                        ProxyErrorReason.AuthenticationRequired);
                }

                var (addressType, addressPayload) = BuildSocks5Address();
                var connectLength = 4 + addressPayload.Length + 2;
                connectRequest = ArrayPool<byte>.Shared.Rent(connectLength);
                int requestIndex = 0;
                connectRequest[requestIndex++] = 0x05;
                connectRequest[requestIndex++] = 0x01;
                connectRequest[requestIndex++] = 0x00;
                connectRequest[requestIndex++] = addressType;
                Buffer.BlockCopy(addressPayload, 0, connectRequest, requestIndex, addressPayload.Length);
                requestIndex += addressPayload.Length;
                connectRequest[requestIndex++] = (byte)(_port >> 8);
                connectRequest[requestIndex] = (byte)(_port & 0xFF);

                await stream.WriteAsync(connectRequest, 0, connectLength, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

                responseHeader = ArrayPool<byte>.Shared.Rent(4);
                await ReadExactAsync(stream, responseHeader, 4, cancellationToken).ConfigureAwait(false);

                if (responseHeader[1] != 0x00)
                {
                    throw new ProxyException($"SOCKS5 proxy connect failed: {DescribeSocks5Status(responseHeader[1])}", ProxyErrorReason.ResponseError);
                }

                var skipLength = responseHeader[3] switch
                {
                    0x01 => 4,
                    0x03 => await ReadLengthAsync(stream, cancellationToken).ConfigureAwait(false),
                    0x04 => 16,
                    _ => throw new IOException("SOCKS5 proxy returned unknown address type")
                };

                if (skipLength > 0)
                {
                    skipBuffer = ArrayPool<byte>.Shared.Rent(skipLength + 2);
                    await ReadExactAsync(stream, skipBuffer, skipLength + 2, cancellationToken).ConfigureAwait(false);
                }

                return stream;
            }
            finally
            {
                if (methodSelection != null)
                {
                    ArrayPool<byte>.Shared.Return(methodSelection);
                }

                if (authRequest != null)
                {
                    ArrayPool<byte>.Shared.Return(authRequest, clearArray: true);
                }

                if (authResponse != null)
                {
                    ArrayPool<byte>.Shared.Return(authResponse, clearArray: true);
                }

                if (connectRequest != null)
                {
                    ArrayPool<byte>.Shared.Return(connectRequest);
                }

                if (responseHeader != null)
                {
                    ArrayPool<byte>.Shared.Return(responseHeader);
                }

                if (skipBuffer != null)
                {
                    ArrayPool<byte>.Shared.Return(skipBuffer);
                }
            }
        }

        private static bool IsSuccessfulHttpProxyResponse(string response, out HttpStatusCode? statusCode, out string statusLine)
        {
            statusCode = null;
            statusLine = null;

            if (string.IsNullOrWhiteSpace(response))
            {
                return false;
            }

            var separator = response.IndexOf('\n');
            statusLine = separator >= 0 ? response[..separator].Trim() : response.Trim();
            var parts = statusLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2 || !int.TryParse(parts[1], out var code))
            {
                return false;
            }

            if (Enum.IsDefined(typeof(HttpStatusCode), code))
            {
                statusCode = (HttpStatusCode)code;
            }

            return code >= 200 && code < 300;
        }

        private static string DescribeSocks4Status(byte status)
        {
            return status switch
            {
                0x5B => "Request rejected or failed.",
                0x5C => "Request rejected: cannot connect to identd on the client.",
                0x5D => "Request rejected: client identd could not confirm the user ID.",
                _ => $"Unknown status 0x{status:X2}."
            };
        }

        private static string DescribeSocks5Status(byte status)
        {
            return status switch
            {
                0x01 => "General SOCKS server failure.",
                0x02 => "Connection not allowed by ruleset.",
                0x03 => "Network unreachable.",
                0x04 => "Host unreachable.",
                0x05 => "Connection refused by destination host.",
                0x06 => "TTL expired.",
                0x07 => "Command not supported.",
                0x08 => "Address type not supported.",
                _ => $"Unknown status 0x{status:X2}."
            };
        }

        private (byte Type, byte[] Payload) BuildSocks5Address()
        {
            var normalizedHost = NormalizeHostname(_host);

            if (!_proxy.ResolveHostnamesRemotely && TryGetIpAddress(normalizedHost, out var ipAddress))
            {
                var bytes = ipAddress.GetAddressBytes();
                var type = ipAddress.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
                return (type, bytes);
            }

            var asciiHost = Encoding.ASCII.GetBytes(normalizedHost ?? string.Empty);
            if (asciiHost.Length > byte.MaxValue)
            {
                throw new ProxyException("SOCKS5 proxy hostname is too long.", ProxyErrorReason.Unsupported);
            }

            var payload = new byte[asciiHost.Length + 1];
            payload[0] = (byte)asciiHost.Length;
            Buffer.BlockCopy(asciiHost, 0, payload, 1, asciiHost.Length);
            return (0x03, payload);
        }

        private static async Task<int> ReadLengthAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var lengthBuffer = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                await ReadExactAsync(stream, lengthBuffer, 1, cancellationToken).ConfigureAwait(false);
                return lengthBuffer[0];
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(lengthBuffer);
            }
        }

        private static bool TryGetIpAddress(string host, out IPAddress address)
        {
            return IPAddress.TryParse(host, out address);
        }

        private string GetProxyAuthority()
        {
            var normalizedHost = NormalizeHostname(_host);
            return FormatAuthority(normalizedHost, _port);
        }

        private static string NormalizeHostname(string host)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                return host;
            }

            if (IPAddress.TryParse(host, out _))
            {
                return host;
            }

            try
            {
                return s_idnMapping.GetAscii(host);
            }
            catch (ArgumentException)
            {
                return host;
            }
        }

        private static string FormatAuthority(string host, int port)
        {
            if (string.IsNullOrEmpty(host))
            {
                return $":{port}";
            }

            return RequiresIpv6Brackets(host)
                ? $"[{host}]:{port}"
                : $"{host}:{port}";
        }

        private static bool RequiresIpv6Brackets(string host)
            => host.IndexOf(':') >= 0 &&
               !host.StartsWith("[", StringComparison.Ordinal) &&
               !host.EndsWith("]", StringComparison.Ordinal);

        private static string BuildProxyAuthorizationHeader(NetworkCredential credential)
        {
            if (credential == null)
            {
                return null;
            }

            var username = credential.UserName ?? string.Empty;
            if (!string.IsNullOrEmpty(credential.Domain))
            {
                username = $"{credential.Domain}\\{username}";
            }

            var password = credential.Password ?? string.Empty;
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
            return $"Basic {token}";
        }

        private static Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
            => ReadExactAsync(stream, buffer, buffer.Length, cancellationToken);

        private static async Task ReadExactAsync(Stream stream, byte[] buffer, int length, CancellationToken cancellationToken)
        {
            int read = 0;
            while (read < length)
            {
                var current = await stream.ReadAsync(buffer, read, length - read, cancellationToken).ConfigureAwait(false);
                if (current == 0)
                {
                    throw new IOException("Unexpected end of stream");
                }

                read += current;
            }
        }

        private static async Task ReadChunkedBodyAsync(Stream stream, IBufferWriter<byte> destination, CancellationToken cancellationToken)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(8192);

            try
            {
                while (true)
                {
                    var line = await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrEmpty(line))
                    {
                        line = await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
                    }

                    var lineSpan = line.AsSpan();
                    var separatorIndex = lineSpan.IndexOf(';');
                    if (separatorIndex >= 0)
                    {
                        lineSpan = lineSpan[..separatorIndex];
                    }

                    lineSpan = TrimAsciiWhitespace(lineSpan);
                    if (!int.TryParse(lineSpan, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var size))
                    {
                        throw new IOException($"Invalid chunk size '{line}'.");
                    }

                    if (size == 0)
                    {
                        await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    var remaining = size;
                    while (remaining > 0)
                    {
                        var toRead = Math.Min(remaining, buffer.Length);
                        var read = await stream.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
                        if (read == 0)
                        {
                            throw new IOException("Unexpected end of stream while reading chunked body.");
                        }

                        WriteToBuffer(destination, buffer.AsSpan(0, read));
                        remaining -= read;
                    }

                    await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private static async Task ReadFixedBodyAsync(Stream stream, IBufferWriter<byte> destination, int length, CancellationToken cancellationToken)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(8192);

            try
            {
                int remaining = length;
                while (remaining > 0)
                {
                    var toRead = Math.Min(buffer.Length, remaining);
                    var read = await stream.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    WriteToBuffer(destination, buffer.AsSpan(0, read));
                    remaining -= read;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private static async Task ReadUntilEndAsync(Stream stream, IBufferWriter<byte> destination, CancellationToken cancellationToken)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(8192);

            try
            {
                while (true)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    WriteToBuffer(destination, buffer.AsSpan(0, read));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private static int GetInitialBodyBufferSize(int contentLength)
        {
            const int DefaultSize = 1024;
            const int MaxInitialSize = 64 * 1024;

            if (contentLength <= 0)
            {
                return DefaultSize;
            }

            if (contentLength < DefaultSize)
            {
                return DefaultSize;
            }

            if (contentLength > MaxInitialSize)
            {
                return MaxInitialSize;
            }

            return contentLength;
        }

        private static void WriteToBuffer(IBufferWriter<byte> writer, ReadOnlySpan<byte> source)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            if (source.Length == 0)
            {
                return;
            }

            var span = writer.GetSpan(source.Length);
            source.CopyTo(span);
            writer.Advance(source.Length);
        }

        private static void ParseBodyMetadata(
            ReadOnlySpan<byte> headerSpan,
            out bool hasContentLength,
            out int contentLength,
            out bool isChunked)
        {
            hasContentLength = false;
            contentLength = 0;
            isChunked = false;

            var index = 0;
            var firstLine = true;

            while (index < headerSpan.Length)
            {
                var remaining = headerSpan.Slice(index);
                var newlineIndex = remaining.IndexOf((byte)'\n');
                if (newlineIndex < 0)
                {
                    break;
                }

                var lineWithTerminator = remaining.Slice(0, newlineIndex + 1);
                index += newlineIndex + 1;

                var line = TrimHeaderLine(lineWithTerminator);
                if (line.Length == 0)
                {
                    continue;
                }

                if (firstLine)
                {
                    firstLine = false;
                    continue;
                }

                var separatorIndex = line.IndexOf((byte)':');
                if (separatorIndex <= 0)
                {
                    continue;
                }

                var name = line.Slice(0, separatorIndex);
                var value = TrimAsciiWhitespace(line.Slice(separatorIndex + 1));

                if (!hasContentLength && EqualsAsciiIgnoreCase(name, "Content-Length") &&
                    Utf8Parser.TryParse(value, out int parsedLength, out int consumed) && consumed == value.Length)
                {
                    hasContentLength = true;
                    contentLength = parsedLength;
                    continue;
                }

                if (!isChunked && EqualsAsciiIgnoreCase(name, "Transfer-Encoding") &&
                    ContainsAsciiIgnoreCase(value, "chunked"))
                {
                    isChunked = true;
                }
            }
        }

        private static ReadOnlySpan<byte> TrimHeaderLine(ReadOnlySpan<byte> line)
        {
            int start = 0;
            int end = line.Length;

            while (start < end && (line[start] == (byte)'\r' || line[start] == (byte)'\n'))
            {
                start++;
            }

            while (end > start && (line[end - 1] == (byte)'\r' || line[end - 1] == (byte)'\n'))
            {
                end--;
            }

            return line.Slice(start, end - start);
        }

        private static ReadOnlySpan<byte> TrimAsciiWhitespace(ReadOnlySpan<byte> value)
        {
            int start = 0;
            int end = value.Length;

            while (start < end && IsAsciiWhitespace(value[start]))
            {
                start++;
            }

            while (end > start && IsAsciiWhitespace(value[end - 1]))
            {
                end--;
            }

            return value.Slice(start, end - start);
        }

        private static ReadOnlySpan<char> TrimAsciiWhitespace(ReadOnlySpan<char> value)
        {
            int start = 0;
            int end = value.Length;

            while (start < end && IsAsciiWhitespace(value[start]))
            {
                start++;
            }

            while (end > start && IsAsciiWhitespace(value[end - 1]))
            {
                end--;
            }

            return value.Slice(start, end - start);
        }

        private static bool EqualsAsciiIgnoreCase(ReadOnlySpan<byte> left, string right)
        {
            if (right == null || left.Length != right.Length)
            {
                return false;
            }

            for (int i = 0; i < right.Length; i++)
            {
                if (ToLowerAscii(left[i]) != ToLowerAscii((byte)right[i]))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool ContainsAsciiIgnoreCase(ReadOnlySpan<byte> span, string value)
        {
            if (value == null || value.Length == 0 || span.Length < value.Length)
            {
                return false;
            }

            for (int i = 0; i <= span.Length - value.Length; i++)
            {
                if (EqualsAsciiIgnoreCase(span.Slice(i, value.Length), value))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsAsciiWhitespace(byte value)
        {
            return value == (byte)' ' || value == (byte)'\t' || value == (byte)'\r' || value == (byte)'\n';
        }

        private static bool IsAsciiWhitespace(char value)
        {
            return value == ' ' || value == '\t' || value == '\r' || value == '\n';
        }

        private static byte ToLowerAscii(byte value)
        {
            if ((uint)(value - 'A') <= ('Z' - 'A'))
            {
                return (byte)(value | 0x20);
            }

            return value;
        }

        private static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
        {
            var writer = new ArrayBufferWriter<byte>(128);
            var single = ArrayPool<byte>.Shared.Rent(1);

            try
            {
                while (true)
                {
                    var read = await stream.ReadAsync(single.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    var span = writer.GetSpan(1);
                    span[0] = single[0];
                    writer.Advance(1);

                    if (single[0] == (byte)'\n')
                    {
                        break;
                    }
                }

                if (writer.WrittenCount == 0)
                {
                    return string.Empty;
                }

                var written = writer.WrittenSpan;
                var end = written.Length;
                while (end > 0 && (written[end - 1] == (byte)'\n' || written[end - 1] == (byte)'\r'))
                {
                    end--;
                }

                if (end <= 0)
                {
                    return string.Empty;
                }

                return Encoding.ASCII.GetString(written.Slice(0, end));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(single);
            }
        }

        private static async Task<HeaderReadResult> ReadHeadersAsync(Stream stream, CancellationToken cancellationToken)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            var headerBuffer = ArrayPool<byte>.Shared.Rent(4096);
            var written = 0;

            while (true)
            {
                if (written == headerBuffer.Length)
                {
                    var newBuffer = ArrayPool<byte>.Shared.Rent(headerBuffer.Length * 2);
                    Buffer.BlockCopy(headerBuffer, 0, newBuffer, 0, written);
                    ArrayPool<byte>.Shared.Return(headerBuffer);
                    headerBuffer = newBuffer;
                }

                var read = await stream.ReadAsync(headerBuffer.AsMemory(written, headerBuffer.Length - written), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    ArrayPool<byte>.Shared.Return(headerBuffer);
                    throw new IOException("Unexpected end of stream while reading headers.");
                }

                var previous = written;
                written += read;
                var searchStart = previous >= 3 ? previous : 3;

                for (int i = searchStart; i <= written - 4; i++)
                {
                    if (headerBuffer[i - 3] == 13 && headerBuffer[i - 2] == 10 && headerBuffer[i - 1] == 13 && headerBuffer[i] == 10)
                    {
                        var headerLength = i + 1;
                        var leftoverCount = written - headerLength;
                        byte[] prefetch = Array.Empty<byte>();

                        if (leftoverCount > 0)
                        {
                            prefetch = ArrayPool<byte>.Shared.Rent(leftoverCount);
                            Buffer.BlockCopy(headerBuffer, headerLength, prefetch, 0, leftoverCount);
                        }

                        return new HeaderReadResult(headerBuffer, headerLength, prefetch, leftoverCount);
                    }
                }
            }
        }

        private readonly struct HeaderReadResult
        {
            public HeaderReadResult(byte[] headerBuffer, int headerLength, byte[] prefetchBuffer, int prefetchLength)
            {
                HeaderBuffer = headerBuffer;
                HeaderLength = headerLength;
                PrefetchBuffer = prefetchBuffer;
                PrefetchLength = prefetchLength;
            }

            public byte[] HeaderBuffer { get; }
            public int HeaderLength { get; }
            public byte[] PrefetchBuffer { get; }
            public int PrefetchLength { get; }
        }

        private readonly struct ProxyResponseBuffer
        {
            public ProxyResponseBuffer(string text, byte[] prefetchBuffer, int prefetchLength)
            {
                Text = text;
                PrefetchBuffer = prefetchBuffer;
                PrefetchLength = prefetchLength;
            }

            public string Text { get; }
            public byte[] PrefetchBuffer { get; }
            public int PrefetchLength { get; }
        }

        private sealed class PrefixedStream : Stream
        {
            private readonly Stream _inner;
            private readonly byte[] _prefix;
            private readonly int _prefixLength;
            private int _offset;

            public PrefixedStream(Stream inner, byte[] prefix, int prefixLength)
            {
                _inner = inner ?? throw new ArgumentNullException(nameof(inner));
                _prefix = prefix ?? Array.Empty<byte>();
                _prefixLength = Math.Min(prefixLength, _prefix.Length);
                _offset = 0;
            }

            public override bool CanRead => _inner.CanRead;
            public override bool CanSeek => false;
            public override bool CanWrite => _inner.CanWrite;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush() => _inner.Flush();

            public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

            public override int Read(byte[] buffer, int offset, int count)
            {
                ValidateBuffer(buffer, offset, count);

                if (_offset < _prefixLength)
                {
                    var available = Math.Min(count, _prefixLength - _offset);
                    Buffer.BlockCopy(_prefix, _offset, buffer, offset, available);
                    _offset += available;
                    return available;
                }

                return _inner.Read(buffer, offset, count);
            }

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_offset < _prefixLength)
                {
                    var available = Math.Min(buffer.Length, _prefixLength - _offset);
                    new ReadOnlyMemory<byte>(_prefix, _offset, available).CopyTo(buffer);
                    _offset += available;
                    return ValueTask.FromResult(available);
                }

                return _inner.ReadAsync(buffer, cancellationToken);
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
                => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
                => _inner.WriteAsync(buffer, offset, count, cancellationToken);

            public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
                => _inner.WriteAsync(buffer, cancellationToken);

            protected override void Dispose(bool disposing)
            {
                // The underlying stream is owned by TlsClient.
            }

            private static void ValidateBuffer(byte[] buffer, int offset, int count)
            {
                if (buffer == null)
                {
                    throw new ArgumentNullException(nameof(buffer));
                }

                if (offset < 0 || count < 0 || buffer.Length - offset < count)
                {
                    throw new ArgumentOutOfRangeException(nameof(offset));
                }
            }
        }

        private sealed class BufferedReadStream : Stream
        {
            private readonly Stream _inner;
            private readonly byte[] _buffer;
            private int _bufferOffset;
            private int _bufferLength;
            private byte[] _prefetch;
            private int _prefetchOffset;
            private readonly int _prefetchLength;
            private bool _disposed;

            public BufferedReadStream(Stream inner, byte[] prefetch, int prefetchLength, int bufferSize = 16384)
            {
                _inner = inner ?? throw new ArgumentNullException(nameof(inner));
                _prefetch = prefetch ?? Array.Empty<byte>();
                _prefetchLength = Math.Min(prefetchLength, _prefetch.Length);
                _buffer = ArrayPool<byte>.Shared.Rent(bufferSize <= 0 ? 16384 : bufferSize);
                _bufferOffset = 0;
                _bufferLength = 0;
            }

            public override bool CanRead => _inner.CanRead;
            public override bool CanSeek => false;
            public override bool CanWrite => _inner.CanWrite;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush() => _inner.Flush();

            public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

            public override int Read(byte[] buffer, int offset, int count)
            {
                ValidateBuffer(buffer, offset, count);

                if (count == 0)
                {
                    return 0;
                }

                var copied = ReadFromPrefetch(buffer.AsSpan(offset, count));
                if (copied > 0)
                {
                    return copied;
                }

                if (_bufferOffset < _bufferLength)
                {
                    var available = Math.Min(count, _bufferLength - _bufferOffset);
                    Buffer.BlockCopy(_buffer, _bufferOffset, buffer, offset, available);
                    _bufferOffset += available;
                    return available;
                }

                var read = _inner.Read(_buffer, 0, _buffer.Length);
                _bufferOffset = 0;
                _bufferLength = read;

                if (read <= 0)
                {
                    return 0;
                }

                var toCopy = Math.Min(count, read);
                Buffer.BlockCopy(_buffer, 0, buffer, offset, toCopy);
                _bufferOffset += toCopy;
                return toCopy;
            }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (buffer.Length == 0)
                {
                    return 0;
                }

                var copied = ReadFromPrefetch(buffer.Span);
                if (copied > 0)
                {
                    return copied;
                }

                if (_bufferOffset < _bufferLength)
                {
                    var available = Math.Min(buffer.Length, _bufferLength - _bufferOffset);
                    _buffer.AsSpan(_bufferOffset, available).CopyTo(buffer.Span);
                    _bufferOffset += available;
                    return available;
                }

                var read = await _inner.ReadAsync(_buffer.AsMemory(0, _buffer.Length), cancellationToken).ConfigureAwait(false);
                _bufferOffset = 0;
                _bufferLength = read;

                if (read <= 0)
                {
                    return 0;
                }

                var toCopy = Math.Min(buffer.Length, read);
                _buffer.AsSpan(0, toCopy).CopyTo(buffer.Span);
                _bufferOffset += toCopy;
                return toCopy;
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                ValidateBuffer(buffer, offset, count);
                return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
                => _inner.WriteAsync(buffer, offset, count, cancellationToken);

            public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
                => _inner.WriteAsync(buffer, cancellationToken);

            protected override void Dispose(bool disposing)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                ArrayPool<byte>.Shared.Return(_buffer);
                _prefetch = Array.Empty<byte>();
            }

            private int ReadFromPrefetch(Span<byte> destination)
            {
                if (_prefetchOffset >= _prefetchLength)
                {
                    return 0;
                }

                var available = Math.Min(destination.Length, _prefetchLength - _prefetchOffset);
                _prefetch.AsSpan(_prefetchOffset, available).CopyTo(destination);
                _prefetchOffset += available;
                if (_prefetchOffset >= _prefetchLength)
                {
                    _prefetch = Array.Empty<byte>();
                }

                return available;
            }

            private static void ValidateBuffer(byte[] buffer, int offset, int count)
            {
                if (buffer == null)
                {
                    throw new ArgumentNullException(nameof(buffer));
                }

                if (offset < 0 || count < 0 || buffer.Length - offset < count)
                {
                    throw new ArgumentOutOfRangeException(nameof(offset));
                }
            }
        }

        private SslClientAuthenticationOptions BuildAuthenticationOptions(string targetHost)
        {
            var sslProtocols = _tlsSettings.EnabledProtocols ?? _fingerprint?.GetSslProtocols() ?? SslProtocols.None;
            var applicationProtocols = _tlsSettings.ApplicationProtocols ?? _fingerprint?.GetApplicationProtocols();

            var options = new SslClientAuthenticationOptions
            {
                TargetHost = NormalizeHostname(targetHost) ?? targetHost,
                EnabledSslProtocols = sslProtocols,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                ClientCertificates = new X509CertificateCollection(),
            };

            var cipherSuites = _fingerprint?.GetCipherSuites();
            if (cipherSuites?.Length > 0 && TlsPlatformSupport.SupportsCipherSuitesPolicy())
            {
                try
                {
                    options.CipherSuitesPolicy = new CipherSuitesPolicy(cipherSuites);
                }
                catch (PlatformNotSupportedException)
                {
                    // Some environments may still reject custom cipher suites despite the capability check.
                }
            }

            if (applicationProtocols != null)
            {
                var protocols = new List<SslApplicationProtocol>();
                foreach (var protocol in applicationProtocols)
                {
                    protocols.Add(new SslApplicationProtocol(Encoding.ASCII.GetBytes(protocol)));
                }

                options.ApplicationProtocols = protocols;
            }

            return options;
        }

        private RemoteCertificateValidationCallback GetProxyValidationCallback()
            => _certificateValidationCallback ?? ((_, _, _, _) => true);

        private RemoteCertificateValidationCallback GetValidationCallback()
        {
            if (_tlsSettings.ValidateCertificate)
            {
                return _tlsSettings.CertificateValidationCallback ?? _certificateValidationCallback;
            }

            return (_, _, _, _) => true;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            CleanupFailedConnection();
        }
    }
}
