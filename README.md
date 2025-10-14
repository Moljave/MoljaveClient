# MojaveHttpClient

> **Raw HTTP/1.1 + TLS JA3 fingerprinting + Proxy + Cookies for .NET/NET Core**  
> Modern, low-level HTTP client for advanced scraping, automation and pentesting scenarios.

---

[![.NET 7/8/9+ Compatible](https://img.shields.io/badge/.NET-6%2F7%2F8%2F9-green.svg)](https://dotnet.microsoft.com/)

---

## 🚀 Features

- **Custom TLS (JA3) Fingerprinting** — simulate Chrome or your own fingerprint, or rotate per request
- **SOCKS4/SOCKS4a/SOCKS5 & HTTP/HTTPS Proxy support** — including authentication and remote DNS
- **Automatic redirects** — configurable at runtime or per request
- **CookieContainer support** — browser-like cookie handling with thread-safety in mind
- **DelegatingHandler pipeline** — plug in your own handlers like with regular `HttpClient`
- **Per-request overrides** — change proxy/TLS/fingerprint/timeout for individual calls
- **Custom headers** — send and control order like a browser
- **Auto-decompression** — supports gzip, deflate, br (brotli)
- **Raw HTTP/1.1 request/response** — maximum control
- **Async/await** — modern, fast, thread-safe
- **Easy to extend** — add more fingerprints or features

---

## 📦 Installation

Copy all files from the `Mojave.Http` folder into your project.

Or, build as your own NuGet package for reuse.

---

## 💡 Usage Example

```csharp
using Mojave.Http;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    static async Task Main()
    {
        // Select browser JA3 fingerprint profile
        var ja3 = JA3FingerprintFactory.GetFingerprint(BrowserJa3Profile.Chrome);

        // Optional: Use CookieContainer and/or Proxy
        var cookies = new CookieContainer();
        var proxy = new WebProxy("socks5://127.0.0.1:9050"); // Or use HTTP proxy

        using var client = new MojaveHttpClient(ja3, cookies, proxy)
        {
            AllowAutoRedirect = true,
            DefaultTimeout = TimeSpan.FromSeconds(20)
        };

        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        request.AddHeaders(@"
            User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
            Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
            Accept-Language: en-US,en;q=0.9
        ");

        var response = await client.SendAsync(request, TimeSpan.FromSeconds(10));
        var html = await response.Content.ReadAsStringAsync();

        Console.WriteLine($"Status: {(int)response.StatusCode}");
        Console.WriteLine("Response:");
        Console.WriteLine(html);
    }
}
```
### 🔧 Advanced configuration

```csharp
var options = new MojaveHttpClientOptions
{
    FingerprintProvider = () => JA3FingerprintFactory.GetFingerprint(BrowserJa3Profile.Chrome),
    CookieContainer = new CookieContainer(),
    DefaultTimeout = TimeSpan.FromSeconds(25),
    ProxyResolver = () => ProxyParser.TryParse(GetNextProxy(), out var proxy)
        ? proxy
        : MojaveProxyOptions.NoProxy
};

// add delegating handlers like with HttpClient
options.DelegatingHandlerFactories.Add(() => new MyTelemetryHandler());

using var client = new MojaveHttpClient(options);

var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/data");
request.ConfigureMojaveOptions(o =>
{
    o.Timeout = TimeSpan.FromSeconds(5);
    o.Proxy = ProxyParser.TryParse("socks5://127.0.0.1:9050", out var proxy)
        ? proxy
        : MojaveProxyOptions.NoProxy;
    o.TlsSettings = new MojaveTlsSettings
    {
        EnabledProtocols = System.Security.Authentication.SslProtocols.Tls13,
        ApplicationProtocols = new[] { "h2", "http/1.1" }
    };
});

var response = await client.SendAsync(request);
```
## 🧪 Custom JA3 Example

```csharp
var ja3 = JA3FingerprintFactory.GetFingerprint(
    BrowserJa3Profile.Custom,
    "771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-45-43-51-27-21-41-28-19,29-23-24,0"
);


