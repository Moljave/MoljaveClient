using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Moljave.Http
{
    public class TlsClient : IDisposable
    {
        private readonly string _host;
        private readonly JA3Fingerprint _ja3Fingerprint;
        private readonly int _port;
        private readonly WebProxy _proxy;
        private TcpClient _tcpClient;
        private SslStream _sslStream;

        public TlsClient(string host, int port = 443, JA3Fingerprint ja3Fingerprint = null, WebProxy proxy = null)
        {
            _host = host;
            _port = port;
            _ja3Fingerprint = ja3Fingerprint ?? JA3Fingerprint.Default;
            _proxy = proxy;
        }

        public void Dispose()
        {
            _sslStream?.Dispose();
            _tcpClient?.Dispose();
        }

        public async Task<byte[]> SendRequestAsync(string request, TimeSpan timeout)
        {
            try
            {
                _tcpClient = new TcpClient();

                if (_proxy != null)
                {
                    string proxyScheme = _proxy.Address.Scheme.ToLower();
                    string proxyHost = _proxy.Address.Host;
                    int proxyPort = _proxy.Address.Port;

                    await _tcpClient.ConnectAsync(proxyHost, proxyPort);

                    if (proxyScheme.StartsWith("socks5"))
                    {
                        await Socks5Handshake(_tcpClient, _proxy, _host, _port, timeout);
                        _sslStream = new SslStream(_tcpClient.GetStream(), false, ServerCertificateCustomValidationCallback);
                    }
                    else // HTTP
                    {
                        var stream = _tcpClient.GetStream();
                        var proxyAuth = GetProxyAuthorizationHeader(_proxy);
                        var connectRequest =
                            $"CONNECT {_host}:{_port} HTTP/1.1\r\nHost: {_host}:{_port}\r\n{proxyAuth}\r\n";
                        var connectRequestBytes = Encoding.ASCII.GetBytes(connectRequest);
                        await stream.WriteAsync(connectRequestBytes, 0, connectRequestBytes.Length);
                        var responseBuffer = new byte[4096];
                        int bytesRead = await stream.ReadAsync(responseBuffer, 0, responseBuffer.Length);
                        var proxyResponse = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);
                        if (!proxyResponse.StartsWith("HTTP/1.1 200"))
                            throw new Exception("Proxy CONNECT failed: " + proxyResponse.Split('\n')[0]);
                        _sslStream = new SslStream(stream, false, ServerCertificateCustomValidationCallback);
                    }
                }
                else
                {
                    await _tcpClient.ConnectAsync(_host, _port);
                    _sslStream = new SslStream(_tcpClient.GetStream(), false, ServerCertificateCustomValidationCallback);
                }

                var clientCertificates = await GetClientCertificatesAsync();
                var cipherSuites = _ja3Fingerprint.GetCipherSuites();
                var applicationProtocols = _ja3Fingerprint.GetApplicationProtocols()
                    .Select(p => new SslApplicationProtocol(Encoding.UTF8.GetBytes(p)))
                    .ToList();

                var sslClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = _host,
                    ClientCertificates = clientCertificates,
                    EnabledSslProtocols = _ja3Fingerprint.GetSslProtocols(),
                    ApplicationProtocols = applicationProtocols,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption
                };

                using var cts = new CancellationTokenSource(timeout);
                await _sslStream.AuthenticateAsClientAsync(sslClientAuthenticationOptions, cts.Token);

                var requestBytes = Encoding.UTF8.GetBytes(request);
                await _sslStream.WriteAsync(requestBytes, 0, requestBytes.Length);

                // Читаем ответ как raw-байты в MemoryStream
                using var memoryStream = new MemoryStream();
                var headerBuffer = new List<byte>();
                var buffer = new byte[1];
                // Чтение до \r\n\r\n
                while (true)
                {
                    int read = await _sslStream.ReadAsync(buffer, 0, 1, cts.Token);
                    if (read == 0) break;
                    headerBuffer.Add(buffer[0]);
                    if (headerBuffer.Count >= 4 &&
                        headerBuffer[^4] == 13 &&
                        headerBuffer[^3] == 10 &&
                        headerBuffer[^2] == 13 &&
                        headerBuffer[^1] == 10)
                        break;
                }

                memoryStream.Write(headerBuffer.ToArray(), 0, headerBuffer.Count);

                // --- Парсим хедеры для определения длины и chunked ---
                var headersStr = Encoding.ASCII.GetString(headerBuffer.ToArray());
                int contentLength = 0;
                bool isChunked = false;

                foreach (var line in headersStr.Split(new[] { "\r\n" }, StringSplitOptions.None))
                {
                    if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                        int.TryParse(line.Substring(15).Trim(), out contentLength);
                    if (line.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase)
                        && line.ToLower().Contains("chunked"))
                        isChunked = true;
                }

                // 1. chunked
                if (isChunked)
                {
                    await ReadChunkedBody(_sslStream, memoryStream, cts.Token);
                }
                // 2. Content-Length
                else if (contentLength > 0)
                {
                    int totalRead = 0;
                    var bodyBuffer = new byte[8192];
                    while (totalRead < contentLength)
                    {
                        int read = await _sslStream.ReadAsync(bodyBuffer, 0, Math.Min(bodyBuffer.Length, contentLength - totalRead), cts.Token);
                        if (read == 0) break;
                        memoryStream.Write(bodyBuffer, 0, read);
                        totalRead += read;
                    }
                }
                // 3. fallback (читаем один блок)
                else
                {
                    var fallbackBuffer = new byte[8192];
                    int read = await _sslStream.ReadAsync(fallbackBuffer, 0, fallbackBuffer.Length, cts.Token);
                    if (read > 0)
                        memoryStream.Write(fallbackBuffer, 0, read);
                }

                return memoryStream.ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                throw;
            }
        }

        private string GetProxyAuthorizationHeader(WebProxy proxy)
        {
            if (proxy?.Credentials is NetworkCredential creds)
            {
                var raw = $"{creds.UserName}:{creds.Password}";
                var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
                return $"Proxy-Authorization: Basic {base64}\r\n";
            }
            return "";
        }

        private async Task Socks5Handshake(TcpClient client, WebProxy proxy, string destHost, int destPort, TimeSpan timeout)
        {
            var stream = client.GetStream();
            NetworkCredential creds = proxy?.Credentials as NetworkCredential;

            byte[] authRequest;
            if (creds != null)
            {
                authRequest = new byte[] { 0x05, 0x02, 0x00, 0x02 };
            }
            else
            {
                authRequest = new byte[] { 0x05, 0x01, 0x00 };
            }
            await stream.WriteAsync(authRequest, 0, creds != null ? 4 : 3);
            await stream.FlushAsync();

            var authReply = new byte[2];
            await ReadExactAsync(stream, authReply, 0, 2, timeout);
            if (authReply[0] != 0x05)
                throw new Exception("SOCKS5: invalid version");
            if (authReply[1] == 0xFF)
                throw new Exception("SOCKS5: no acceptable authentication methods");

            if (authReply[1] == 0x02)
            {
                byte[] uname = Encoding.ASCII.GetBytes(creds.UserName);
                byte[] pwd = Encoding.ASCII.GetBytes(creds.Password);
                byte[] upRequest = new byte[3 + uname.Length + pwd.Length];
                upRequest[0] = 0x01;
                upRequest[1] = (byte)uname.Length;
                Buffer.BlockCopy(uname, 0, upRequest, 2, uname.Length);
                upRequest[2 + uname.Length] = (byte)pwd.Length;
                Buffer.BlockCopy(pwd, 0, upRequest, 3 + uname.Length, pwd.Length);
                await stream.WriteAsync(upRequest, 0, upRequest.Length);
                await stream.FlushAsync();
                var upReply = new byte[2];
                await ReadExactAsync(stream, upReply, 0, 2, timeout);
                if (upReply[1] != 0x00)
                    throw new Exception("SOCKS5: Username/Password auth failed");
            }

            byte[] hostBytes = Encoding.ASCII.GetBytes(destHost);
            byte[] req = new byte[7 + hostBytes.Length];
            req[0] = 0x05;
            req[1] = 0x01;
            req[2] = 0x00;
            req[3] = 0x03;
            req[4] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, req, 5, hostBytes.Length);
            req[5 + hostBytes.Length] = (byte)(destPort >> 8);
            req[6 + hostBytes.Length] = (byte)(destPort & 0xFF);
            await stream.WriteAsync(req, 0, req.Length);
            await stream.FlushAsync();

            var resp = new byte[4];
            await ReadExactAsync(stream, resp, 0, 4, timeout);

            int addrLen;
            if (resp[3] == 0x01)
                addrLen = 4;
            else if (resp[3] == 0x03)
            {
                var lenBuf = new byte[1];
                await ReadExactAsync(stream, lenBuf, 0, 1, timeout);
                addrLen = lenBuf[0];
            }
            else if (resp[3] == 0x04)
                addrLen = 16;
            else
                throw new Exception("SOCKS5: unknown address type");
            var skip = new byte[addrLen + 2];
            await ReadExactAsync(stream, skip, 0, skip.Length, timeout);
        }

        private async Task ReadExactAsync(NetworkStream stream, byte[] buffer, int offset, int count, TimeSpan timeout)
        {
            int read = 0;
            var cts = new CancellationTokenSource(timeout);
            while (read < count)
            {
                int r = await stream.ReadAsync(buffer, offset + read, count - read, cts.Token);
                if (r == 0) throw new IOException("SOCKS5: EOF");
                read += r;
            }
        }

        private async Task ReadChunkedBody(Stream stream, MemoryStream memoryStream, CancellationToken token)
        {
            while (true)
            {
                string chunkSizeLine = await ReadLineAsync(stream, token);
                if (string.IsNullOrWhiteSpace(chunkSizeLine))
                    chunkSizeLine = await ReadLineAsync(stream, token);

                int chunkSize = int.Parse(chunkSizeLine.Split(';')[0], System.Globalization.NumberStyles.HexNumber);
                if (chunkSize == 0)
                {
                    await ReadLineAsync(stream, token); // trailing CRLF
                    break;
                }

                var chunkBuffer = new byte[chunkSize];
                int totalRead = 0;
                while (totalRead < chunkSize)
                {
                    int read = await stream.ReadAsync(chunkBuffer, totalRead, chunkSize - totalRead, token);
                    if (read == 0) break;
                    totalRead += read;
                }
                memoryStream.Write(chunkBuffer, 0, totalRead);
                await ReadLineAsync(stream, token); // CRLF после чанка
            }
        }

        private async Task<string> ReadLineAsync(Stream stream, CancellationToken token)
        {
            var sb = new List<byte>();
            var buffer = new byte[1];
            while (true)
            {
                int read = await stream.ReadAsync(buffer, 0, 1, token);
                if (read == 0) break;
                sb.Add(buffer[0]);
                if (buffer[0] == (byte)'\n') break;
            }
            return Encoding.ASCII.GetString(sb.ToArray()).TrimEnd('\r', '\n');
        }

        private async Task<X509CertificateCollection> GetClientCertificatesAsync()
        {
            var certificates = new X509CertificateCollection();
            return await Task.FromResult(certificates);
        }

        private bool ServerCertificateCustomValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            => true;
    }
}
