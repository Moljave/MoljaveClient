# MoljaveClient Examples

## Configure the client with presets and cookies
```csharp
var options = new MojaveHttpClientOptions
{
    FingerprintPreset = Ja3Preset.Chrome,
    MaxConnectionRetries = 1,
    ConnectionRetryDelay = TimeSpan.FromMilliseconds(100)
};

// keep only the cookies you need
options.CookieManager.RemoveCookies(new List<string> { "session", "auth_token" });

using var client = new MojaveHttpClient(options);
client.CookieManager.ChangeCookieValue("session", "fresh-value");
```

## Send HTTP/1.1 requests through an HTTP proxy
```csharp
var request = new HttpRequestMessage(HttpMethod.Get, "http://example.org/api");

request.ConfigureMojaveOptions(o =>
{
    o.Proxy = ProxyParser.TryParse("http://127.0.0.1:8080", out var proxy)
        ? proxy
        : MojaveProxyOptions.NoProxy;
    o.Timeout = TimeSpan.FromSeconds(5);
});

using var client = new MojaveHttpClient();
var response = await client.SendAsync(request);
```

## Pin a custom JA3 fingerprint
```csharp
var customJa3 = JA3FingerprintParser.Parse(
    "771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-45-43-51-27-21-41-28-19,29-23-24,0");

using var client = new MojaveHttpClient();
client.UseFingerprintProvider(() => customJa3, rotateImmediately: true);
```

## Rotate proxies while keeping cookies
```csharp
var proxies = new Queue<string>(new[]
{
    "socks5://127.0.0.1:1080",
    "http://127.0.0.1:8888"
});

var options = new MojaveHttpClientOptions
{
    ProxyResolver = () =>
    {
        var next = proxies.Dequeue();
        proxies.Enqueue(next);
        return ProxyParser.TryParse(next, out var proxy)
            ? proxy
            : MojaveProxyOptions.NoProxy;
    }
};

using var client = new MojaveHttpClient(options);
client.CookieManager.ChangeCookieValue("session", Guid.NewGuid().ToString("N"));
var rotatedResponse = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://example.com"));
```
