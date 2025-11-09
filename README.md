# MojaveHttpClient

> **Raw HTTP/1.1 + TLS JA3 fingerprinting + Proxy + Cookies for .NET/NET Core**
> Modern, low-level HTTP client for advanced scraping, automation and pentesting scenarios.
> **Production ready for Windows 10/11 environments.**

---

[![.NET 7/8/9+ Compatible](https://img.shields.io/badge/.NET-6%2F7%2F8%2F9-green.svg)](https://dotnet.microsoft.com/)

---

## 🖥️ System Requirements

- **Operating system:** Windows 10 version 2004 (build 19041) or newer (including Windows 11)
- **Runtime:** .NET 6.0 or later

The library validates the platform at runtime and will throw a `PlatformNotSupportedException` if it is used on unsupported operating systems. This avoids failures that were previously triggered when instantiating TLS policies on other platforms.

---

## ✅ Production Deployment Checklist

- Build your application in **Release** configuration (`dotnet build -c Release`).
- Run your automated tests against the Release build before deployment.
- Ensure that all target machines run **Windows 10 version 2004 (build 19041) or newer** with the latest security updates.
- Configure monitoring/telemetry around HTTP request success and failure rates.
- Keep TLS fingerprints rotated according to your security posture with `MojaveHttpClient.RotateFingerprint()`.

---

## 🚀 Features

- **Custom TLS (JA3) Fingerprinting** — automatically generated per-client, rotate with a single call, or supply your own profile
- **SOCKS4/SOCKS4a/SOCKS5 & HTTP/HTTPS Proxy support** — including authentication and remote DNS
- **Automatic redirects** — configurable at runtime or per request
- **Advanced cookie management** — tweak, clear or replace cookies at runtime with thread-safety in mind
- **DelegatingHandler pipeline** — plug in your own handlers like with regular `HttpClient`
- **Per-request overrides** — change proxy/TLS/fingerprint/timeout for individual calls
- **Custom headers** — send and control order like a browser
- **Auto-decompression** — supports gzip, deflate, br (brotli)
- **Raw HTTP/1.1 & HTTP/2 request/response** — maximum control with on-the-fly protocol selection
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
        using var client = new MojaveHttpClient()
        {
            AllowAutoRedirect = true,
            DefaultTimeout = TimeSpan.FromSeconds(20)
        };

        // Optionally plug in a proxy at runtime
        client.SetProxy(new WebProxy("socks5://127.0.0.1:9050"));

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
    DefaultTimeout = TimeSpan.FromSeconds(25),
    MaxConnectionRetries = 2,
    ConnectionRetryDelay = TimeSpan.FromMilliseconds(200),
    MaxConnectionsPerHost = 6000,
    ProxyResolver = () => ProxyParser.TryParse(GetNextProxy(), out var proxy)
        ? proxy
        : MojaveProxyOptions.NoProxy
};

// add delegating handlers like with HttpClient
options.DelegatingHandlerFactories.Add(() => new MyTelemetryHandler());

using var client = new MojaveHttpClient(options);

// choose a built-in JA3 preset (Disabled, Default, Chrome)
options.FingerprintPreset = Ja3Preset.Chrome;

// rotate to a fresh JA3 fingerprint whenever you need
client.RotateFingerprint();

// set or mutate cookies at runtime
client.CookieManager.SetCookie("example.com", "session", "12345");

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

### 🍪 Cookie management cheatsheet

```csharp
// Update a cookie value wherever it exists
client.CookieManager.ChangeCookieValue("session", "new-value");

// Remove a cookie globally or for a specific domain
client.CookieManager.RemoveCookie("session");
client.CookieManager.RemoveCookie("example.com", "session");

// Drop every cookie except the ones you want to keep
client.CookieManager.RemoveCookies(new List<string> { "session", "auth_token" });

// Clear cookies for a single domain or every domain
client.ClearCookiesForDomain("example.com");
client.ClearAllCookies();
```

### 🧭 Hot proxy switching

```csharp
// Use a direct proxy instance
client.SetProxy(new WebProxy("http://127.0.0.1:8888"));

// Swap proxies on the fly without re-enabling a disabled proxy
client.ChangeProxy(new WebProxy("socks5://127.0.0.1:9050"));

// Dynamically resolve proxies (e.g. rotating provider)
client.SetProxyResolver(() => ProxyParser.TryParse(GetNextProxy(), out var proxy)
    ? proxy
    : MojaveProxyOptions.NoProxy);

// Temporarily stop using the configured proxy and enable it again later
client.DisableProxy();
client.EnableProxy();
```
## 🧪 Custom JA3 Example

```csharp
// Parse a custom JA3 fingerprint and pin it to the client
var ja3 = JA3FingerprintParser.Parse(
    "771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-45-43-51-27-21-41-28-19,29-23-24,0");

client.UseFingerprintProvider(() => ja3);
```
