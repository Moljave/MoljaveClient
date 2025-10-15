using System;
using System.Collections.Generic;
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
        private readonly string _host;
        private readonly int _port;
        private readonly JA3Fingerprint _fingerprint;
        private readonly ProxyDescriptor _proxy;
        private readonly MojaveTlsSettings _tlsSettings;
        private readonly RemoteCertificateValidationCallback _certificateValidationCallback;

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
            RemoteCertificateValidationCallback certificateValidationCallback)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _fingerprint = fingerprint ?? JA3Fingerprint.Default;
            _proxy = proxy;
            _tlsSettings = tlsSettings ?? MojaveTlsSettings.Default;
            _certificateValidationCallback = certificateValidationCallback ?? ((_, _, _, _) => true);
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
            var headerBuffer = new List<byte>();
            var buffer = new byte[1];

            while (true)
            {
                var read = await activeStream.ReadAsync(buffer, 0, 1, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new IOException("Unexpected end of stream while reading headers.");
                }

                headerBuffer.Add(buffer[0]);
                if (headerBuffer.Count >= 4 &&
                    headerBuffer[^4] == 13 &&
                    headerBuffer[^3] == 10 &&
                    headerBuffer[^2] == 13 &&
                    headerBuffer[^1] == 10)
                {
                    break;
                }
            }

            var headerBytes = headerBuffer.ToArray();
            memoryStream.Write(headerBytes, 0, headerBytes.Length);

            var headersText = Encoding.ASCII.GetString(headerBytes);
            int contentLength = 0;
            bool isChunked = false;

            foreach (var line in headersText.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                {
                    int.TryParse(line[15..].Trim(), out contentLength);
                }

                if (line.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase) &&
                    line.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    isChunked = true;
                }
            }

            if (isChunked)
            {
                await ReadChunkedBodyAsync(activeStream, memoryStream, cancellationToken).ConfigureAwait(false);
            }
            else if (contentLength > 0)
            {
                await ReadFixedBodyAsync(activeStream, memoryStream, contentLength, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await ReadUntilEndAsync(activeStream, memoryStream, cancellationToken).ConfigureAwait(false);
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

            _tcpClient = new TcpClient
            {
                NoDelay = true
            };

            if (_proxy == null)
            {
                await _tcpClient.ConnectAsync(_host, _port).WaitAsync(cancellationToken).ConfigureAwait(false);
                _transportStream = _tcpClient.GetStream();
            }
            else
            {
                await ConnectThroughProxyAsync(cancellationToken).ConfigureAwait(false);
            }

            return _transportStream;
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
            var authenticationOptions = BuildAuthenticationOptions();
            await _sslStream.AuthenticateAsClientAsync(authenticationOptions, cancellationToken).ConfigureAwait(false);
            return _sslStream;
        }

        private async Task ConnectThroughProxyAsync(CancellationToken cancellationToken)
        {
            var proxyHost = _proxy.Host;
            var proxyPort = _proxy.Port;

            await _tcpClient.ConnectAsync(proxyHost, proxyPort).WaitAsync(cancellationToken).ConfigureAwait(false);
            var stream = _tcpClient.GetStream();

            switch (_proxy.Scheme)
            {
                case ProxyScheme.Http:
                case ProxyScheme.Https:
                    _transportStream = await EstablishHttpTunnelAsync(stream, cancellationToken).ConfigureAwait(false);
                    break;
                case ProxyScheme.Socks4:
                case ProxyScheme.Socks4a:
                    _transportStream = await EstablishSocks4TunnelAsync(stream, cancellationToken).ConfigureAwait(false);
                    break;
                case ProxyScheme.Socks5:
                    _transportStream = await EstablishSocks5TunnelAsync(stream, cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    throw new NotSupportedException($"Proxy scheme {_proxy.Scheme} is not supported.");
            }
        }

        private async Task<Stream> EstablishHttpTunnelAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var builder = new StringBuilder();
            builder.AppendLine($"CONNECT {_host}:{_port} HTTP/1.1");
            builder.AppendLine($"Host: {_host}:{_port}");

            if (_proxy.Credentials is NetworkCredential creds)
            {
                var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{creds.UserName}:{creds.Password}"));
                builder.AppendLine($"Proxy-Authorization: Basic {token}");
            }

            builder.AppendLine();

            var requestBytes = Encoding.ASCII.GetBytes(builder.ToString());
            await stream.WriteAsync(requestBytes, 0, requestBytes.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var response = await ReadHttpProxyResponseAsync(stream, cancellationToken).ConfigureAwait(false);
            if (!response.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase) &&
                !response.StartsWith("HTTP/1.0 200", StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException($"Proxy CONNECT failed: {response.Split('\n')[0]}".Trim());
            }

            return stream;
        }

        private static async Task<string> ReadHttpProxyResponseAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var builder = new StringBuilder();
            var buffer = new byte[1];
            while (true)
            {
                var read = await stream.ReadAsync(buffer, 0, 1, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                builder.Append((char)buffer[0]);
                if (builder.Length >= 4 &&
                    builder[^4] == '\r' &&
                    builder[^3] == '\n' &&
                    builder[^2] == '\r' &&
                    builder[^1] == '\n')
                {
                    break;
                }
            }

            return builder.ToString();
        }

        private async Task<Stream> EstablishSocks4TunnelAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var addressBytes = TryGetIpAddress(_host, out var ipAddress) && !_proxy.ResolveHostnamesRemotely
                ? ipAddress.GetAddressBytes()
                : new byte[] { 0x00, 0x00, 0x00, 0x01 };

            var userId = _proxy.Credentials?.UserName ?? string.Empty;
            var hostBytes = Encoding.ASCII.GetBytes(_host);

            bool useDomain = addressBytes[0] == 0x00 && addressBytes[1] == 0x00 && addressBytes[2] == 0x00 && addressBytes[3] == 0x01;
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
                throw new IOException($"SOCKS4 proxy connection failed with status {response[1]:X2}");
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
                throw new IOException("SOCKS5 proxy handshake failed: invalid version");
            }

            if (methodSelection[1] == 0x02)
            {
                if (!hasCredentials)
                {
                    throw new IOException("SOCKS5 proxy requires authentication but no credentials were provided.");
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
                    throw new IOException("SOCKS5 proxy authentication failed");
                }
            }
            else if (methodSelection[1] == 0xFF)
            {
                throw new IOException("SOCKS5 proxy does not accept provided authentication methods");
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
                throw new IOException($"SOCKS5 proxy connect failed with status {responseHeader[1]:X2}");
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

        private (byte Type, byte[] Payload) BuildSocks5Address()
        {
            if (!_proxy.ResolveHostnamesRemotely && TryGetIpAddress(_host, out var ipAddress))
            {
                var bytes = ipAddress.GetAddressBytes();
                var type = ipAddress.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
                return (type, bytes);
            }

            var hostBytes = Encoding.ASCII.GetBytes(_host);
            var payload = new byte[hostBytes.Length + 1];
            payload[0] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, payload, 1, hostBytes.Length);
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

        private SslClientAuthenticationOptions BuildAuthenticationOptions()
        {
            var sslProtocols = _tlsSettings.EnabledProtocols ?? _fingerprint.GetSslProtocols();
            var applicationProtocols = _tlsSettings.ApplicationProtocols ?? _fingerprint.GetApplicationProtocols();

            var options = new SslClientAuthenticationOptions
            {
                TargetHost = _host,
                EnabledSslProtocols = sslProtocols,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                ClientCertificates = new X509CertificateCollection(),
            };

            var cipherSuites = _fingerprint.GetCipherSuites();
            if (cipherSuites?.Length > 0)
            {
                try
                {
                    options.CipherSuitesPolicy = new CipherSuitesPolicy(cipherSuites);
                }
                catch (PlatformNotSupportedException)
                {
                    // The current platform does not support configuring cipher suites.
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
            _sslStream?.Dispose();
            _transportStream?.Dispose();
            _tcpClient?.Dispose();
        }
    }
}
