using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
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
            _fingerprint = fingerprint ?? JA3Fingerprint.Default;
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

        public async Task<byte[]> SendRequestAsync(byte[] requestBytes, CancellationToken cancellationToken, bool useTls)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(TlsClient));
            }

            if (requestBytes == null)
            {
                throw new ArgumentNullException(nameof(requestBytes));
            }

            var activeStream = await GetActiveStreamAsync(useTls, cancellationToken).ConfigureAwait(false);

            await activeStream.WriteAsync(requestBytes, 0, requestBytes.Length, cancellationToken).ConfigureAwait(false);
            await activeStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            using var memoryStream = new MemoryStream();
            var headerResult = await ReadHeadersAsync(activeStream, cancellationToken).ConfigureAwait(false);
            memoryStream.Write(headerResult.HeaderBuffer, 0, headerResult.HeaderLength);

            var headersText = Encoding.ASCII.GetString(headerResult.HeaderBuffer, 0, headerResult.HeaderLength);
            int contentLength = 0;
            bool hasContentLength = false;
            bool isChunked = false;

            foreach (var line in headersText.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                {
                    hasContentLength = true;
                    int.TryParse(line[15..].Trim(), out contentLength);
                }

                if (line.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase) &&
                    line.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    isChunked = true;
                }
            }

            using var responseStream = new BufferedReadStream(activeStream, headerResult.PrefetchBuffer, headerResult.PrefetchLength);

            if (isChunked)
            {
                await ReadChunkedBodyAsync(responseStream, memoryStream, cancellationToken).ConfigureAwait(false);
            }
            else if (hasContentLength)
            {
                await ReadFixedBodyAsync(responseStream, memoryStream, contentLength, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await ReadUntilEndAsync(responseStream, memoryStream, cancellationToken).ConfigureAwait(false);
            }

            return memoryStream.ToArray();
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
                : new byte[] { 0x00, 0x00, 0x00, 0x01 };

            var userId = _proxy.Credentials?.UserName ?? string.Empty;
            var hostBytes = Encoding.ASCII.GetBytes(normalizedHost ?? string.Empty);

            bool useDomain = addressBytes[0] == 0x00 && addressBytes[1] == 0x00 && addressBytes[2] == 0x00 && addressBytes[3] == 0x01;
            if (useDomain && hostBytes.Length > byte.MaxValue)
            {
                throw new ProxyException("SOCKS4 proxy hostname is too long.", ProxyErrorReason.Unsupported);
            }
            var buffer = new byte[9 + userId.Length + (useDomain ? hostBytes.Length + 1 : 0)];
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

            var response = new byte[8];
            await ReadExactAsync(stream, response, cancellationToken).ConfigureAwait(false);

            if (response[1] != 0x5A)
            {
                throw new ProxyException($"SOCKS4 proxy connection failed: {DescribeSocks4Status(response[1])}", ProxyErrorReason.ResponseError);
            }

            return stream;
        }

        private async Task<Stream> EstablishSocks5TunnelAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var hasCredentials = _proxy.Credentials is NetworkCredential;
            var greeting = hasCredentials
                ? new byte[] { 0x05, 0x02, 0x00, 0x02 }
                : new byte[] { 0x05, 0x01, 0x00 };

            await stream.WriteAsync(greeting, 0, greeting.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var methodSelection = new byte[2];
            await ReadExactAsync(stream, methodSelection, cancellationToken).ConfigureAwait(false);

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
                var authRequest = new byte[3 + userBytes.Length + passBytes.Length];
                int index = 0;
                authRequest[index++] = 0x01;
                authRequest[index++] = (byte)userBytes.Length;
                Buffer.BlockCopy(userBytes, 0, authRequest, index, userBytes.Length);
                index += userBytes.Length;
                authRequest[index++] = (byte)passBytes.Length;
                Buffer.BlockCopy(passBytes, 0, authRequest, index, passBytes.Length);

                await stream.WriteAsync(authRequest, 0, authRequest.Length, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

                var authResponse = new byte[2];
                await ReadExactAsync(stream, authResponse, cancellationToken).ConfigureAwait(false);
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
            var connectRequest = new byte[4 + addressPayload.Length + 2];
            int requestIndex = 0;
            connectRequest[requestIndex++] = 0x05;
            connectRequest[requestIndex++] = 0x01;
            connectRequest[requestIndex++] = 0x00;
            connectRequest[requestIndex++] = addressType;
            Buffer.BlockCopy(addressPayload, 0, connectRequest, requestIndex, addressPayload.Length);
            requestIndex += addressPayload.Length;
            connectRequest[requestIndex++] = (byte)(_port >> 8);
            connectRequest[requestIndex] = (byte)(_port & 0xFF);

            await stream.WriteAsync(connectRequest, 0, connectRequest.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var responseHeader = new byte[4];
            await ReadExactAsync(stream, responseHeader, cancellationToken).ConfigureAwait(false);

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
                var skipBuffer = new byte[skipLength + 2];
                await ReadExactAsync(stream, skipBuffer, cancellationToken).ConfigureAwait(false);
            }

            return stream;
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
            var lengthBuffer = new byte[1];
            await ReadExactAsync(stream, lengthBuffer, cancellationToken).ConfigureAwait(false);
            return lengthBuffer[0];
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

        private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            int read = 0;
            while (read < buffer.Length)
            {
                var current = await stream.ReadAsync(buffer, read, buffer.Length - read, cancellationToken).ConfigureAwait(false);
                if (current == 0)
                {
                    throw new IOException("Unexpected end of stream");
                }

                read += current;
            }
        }

        private static async Task ReadChunkedBodyAsync(Stream stream, MemoryStream destination, CancellationToken cancellationToken)
        {
            while (true)
            {
                var line = await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrEmpty(line))
                {
                    line = await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
                }

                var size = int.Parse(line.Split(';')[0], System.Globalization.NumberStyles.HexNumber);
                if (size == 0)
                {
                    await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
                    break;
                }

                var buffer = new byte[size];
                await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
                destination.Write(buffer, 0, buffer.Length);
                await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
            }
        }

        private static async Task ReadFixedBodyAsync(Stream stream, MemoryStream destination, int length, CancellationToken cancellationToken)
        {
            var buffer = new byte[8192];
            int remaining = length;
            while (remaining > 0)
            {
                var toRead = Math.Min(buffer.Length, remaining);
                var read = await stream.ReadAsync(buffer, 0, toRead, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                destination.Write(buffer, 0, read);
                remaining -= read;
            }
        }

        private static async Task ReadUntilEndAsync(Stream stream, MemoryStream destination, CancellationToken cancellationToken)
        {
            var buffer = new byte[8192];
            while (true)
            {
                var read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                destination.Write(buffer, 0, read);
            }
        }

        private static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
        {
            var buffer = new List<byte>();
            var single = new byte[1];
            while (true)
            {
                var read = await stream.ReadAsync(single, 0, 1, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                buffer.Add(single[0]);
                if (single[0] == (byte)'\n')
                {
                    break;
                }
            }

            return Encoding.ASCII.GetString(buffer.ToArray()).TrimEnd('\r', '\n');
        }

        private static async Task<HeaderReadResult> ReadHeadersAsync(Stream stream, CancellationToken cancellationToken)
        {
            var writer = new ArrayBufferWriter<byte>(4096);
            var buffer = ArrayPool<byte>.Shared.Rent(8192);

            try
            {
                while (true)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        throw new IOException("Unexpected end of stream while reading headers.");
                    }

                    var previousLength = writer.WrittenCount;
                    writer.Write(buffer.AsSpan(0, read));
                    var span = writer.WrittenSpan;
                    var searchStart = previousLength >= 3 ? previousLength : 3;

                    for (int i = searchStart; i < span.Length; i++)
                    {
                        if (span[i - 3] == 13 && span[i - 2] == 10 && span[i - 1] == 13 && span[i] == 10)
                        {
                            var headerLength = i + 1;
                            var headerBuffer = new byte[headerLength];
                            span.Slice(0, headerLength).CopyTo(headerBuffer);

                            var leftoverCount = span.Length - headerLength;
                            byte[] prefetch = Array.Empty<byte>();
                            if (leftoverCount > 0)
                            {
                                prefetch = new byte[leftoverCount];
                                span.Slice(headerLength, leftoverCount).CopyTo(prefetch);
                            }

                            return new HeaderReadResult(headerBuffer, headerLength, prefetch, leftoverCount);
                        }
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
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
            var sslProtocols = _tlsSettings.EnabledProtocols ?? _fingerprint.GetSslProtocols();
            var applicationProtocols = _tlsSettings.ApplicationProtocols ?? _fingerprint.GetApplicationProtocols();

            var options = new SslClientAuthenticationOptions
            {
                TargetHost = NormalizeHostname(targetHost) ?? targetHost,
                EnabledSslProtocols = sslProtocols,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                ClientCertificates = new X509CertificateCollection(),
            };

            var cipherSuites = _fingerprint.GetCipherSuites();
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
