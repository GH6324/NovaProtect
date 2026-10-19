using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

var passed = 0;
void Check(bool value, string name)
{
    if (!value) throw new InvalidOperationException("FAIL: " + name);
    Console.WriteLine("[ OK ] " + name);
    passed++;
}

HttpResponseMessage Response(string body, string mediaType = "application/json", HttpStatusCode status = HttpStatusCode.OK) =>
    new(status) { Content = new StringContent(body, Encoding.UTF8, mediaType) };

HttpResponseMessage Binary(byte[] content, HttpStatusCode status = HttpStatusCode.OK) =>
    new(status)
    {
        Content = new ByteArrayContent(content)
        {
            Headers = { ContentType = new MediaTypeHeaderValue("application/vnd.microsoft.portable-executable") }
        }
    };

HttpResponseMessage Chunked(byte[] content, string mediaType = "application/octet-stream") =>
    new(HttpStatusCode.OK)
    {
        Content = new StreamContent(new MemoryStream(content))
        {
            Headers = { ContentType = new MediaTypeHeaderValue(mediaType) }
        }
    };

var endpoint = new Uri("https://nova.fbi.plus/");
var current = ProductInfo.Version;
var fixtureHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("novaprotect-update-fixture"))).ToLowerInvariant();
string UpdateJson(string clientVersion, string fileName, long size, string sha256, string downloadPath, string minimumClientVersion, bool forceUpdate) =>
    JsonSerializer.Serialize(new
    {
        clientVersion,
        websiteVersion = "2.2.11",
        fileName,
        size,
        sha256,
        downloadPath,
        minimumClientVersion,
        forceUpdate,
        releaseNotes = "Smoke fixture release.",
        publishedAt = "2026-10-18T00:00:00+00:00"
    });

var payload = UpdateJson(current, $"NovaProtect-Setup-{current}.exe", 4096, fixtureHash,
    $"/api/releases/current/download?version={current}&sha256={fixtureHash}", "2.2.6", false);

using (var client = new UpdateClient(endpoint, new FakeHandler((request, _) =>
{
    Check(request.RequestUri?.Host == "nova.fbi.plus" && request.RequestUri.Scheme == "https", "production endpoint is HTTPS");
    Check(request.Headers.CacheControl is { NoStore: true, NoCache: true }, "client requests bypass cache");
    Check(request.Headers.TryGetValues("X-NovaProtect-Client", out var clientHeader) && clientHeader.SequenceEqual(new[] { "1" }), "client routing hint is present");
    return Task.FromResult(Response(payload));
})))
{
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update is not null, "typed current-version update metadata");
    Check(result.Update!.ClientVersion == current && !result.Update.IsNewer && !result.Update.IsRequired, "same version is not offered as an update (downgrade gate)");
    Check(result.Update.ReleaseNotes == "Smoke fixture release." && result.Update.Size == 4096, "release metadata is parsed");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response(
    UpdateJson("2.3.0", "NovaProtect-Setup-2.3.0.exe", 8192, fixtureHash,
        "/api/releases/current/download?version=2.3.0&sha256=" + fixtureHash, "2.2.6", true))))))
{
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update is { IsNewer: true, IsRequired: true, ForceUpdate: true }, "newer forced update is marked required");
}

var invalid = new (string Name, string Body, string MediaType, HttpStatusCode Status, string? Expected)[]
{
    ("CDN HTML 200", "<html>Guard</html>", "text/html", HttpStatusCode.OK, null),
    ("CDN HTML 403", "<html>Guard</html>", "text/html", HttpStatusCode.Forbidden, null),
    ("CDN HTTP 444", "", "text/html", (HttpStatusCode)444, "CDNfly"),
    ("upstream HTML 502", "<html>Unavailable</html>", "text/html", HttpStatusCode.BadGateway, null),
    ("redirect 302", "", "text/html", HttpStatusCode.Found, null),
    ("invalid JSON", "{broken", "application/json", HttpStatusCode.OK, null),
    ("array root", "[]", "application/json", HttpStatusCode.OK, null),
    ("null root", "null", "application/json", HttpStatusCode.OK, null),
    ("string root", "\"invalid\"", "application/json", HttpStatusCode.OK, null),
    ("empty object", "{}", "application/json", HttpStatusCode.OK, null),
    ("string client version", UpdateJson("2.2", "NovaProtect-Setup-2.2.exe", 1, fixtureHash, "/api/releases/current/download", "2.2.6", false), "application/json", HttpStatusCode.OK, null),
    ("minimum above remote", UpdateJson(current, $"NovaProtect-Setup-{current}.exe", 1, fixtureHash, "/api/releases/current/download", "9.9.9", false), "application/json", HttpStatusCode.OK, null),
    ("wrong installer name", UpdateJson(current, "setup.exe", 1, fixtureHash, "/api/releases/current/download", "2.2.6", false), "application/json", HttpStatusCode.OK, null),
    ("installer version mismatch", UpdateJson(current, "NovaProtect-Setup-2.2.6.exe", 1, fixtureHash, "/api/releases/current/download", "2.2.6", false), "application/json", HttpStatusCode.OK, null),
    ("bad sha256", UpdateJson(current, $"NovaProtect-Setup-{current}.exe", 1, "notahash", "/api/releases/current/download", "2.2.6", false), "application/json", HttpStatusCode.OK, null),
    ("foreign download host", UpdateJson(current, $"NovaProtect-Setup-{current}.exe", 1, fixtureHash, "https://evil.example/download", "2.2.6", false), "application/json", HttpStatusCode.OK, null),
    ("download query mismatch", UpdateJson(current, $"NovaProtect-Setup-{current}.exe", 1, fixtureHash, $"/api/releases/current/download?version={current}&sha256={new string('0', 64)}", "2.2.6", false), "application/json", HttpStatusCode.OK, null),
    ("oversized release notes", UpdateJson(current, $"NovaProtect-Setup-{current}.exe", 1, fixtureHash, "/api/releases/current/download", "2.2.6", false).Replace("Smoke fixture release.", new string('x', 13000)), "application/json", HttpStatusCode.OK, null),
    ("known oversized body", new string(' ', 300000) + payload, "application/json", HttpStatusCode.OK, null)
};

foreach (var item in invalid)
{
    using var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response(item.Body, item.MediaType, item.Status))));
    var result = await client.CheckForUpdateAsync();
    Check(result.Update is null && result.Error is not null, item.Name + " fails safely");
    if (item.Expected is not null)
        Check(result.Error!.Contains(item.Expected, StringComparison.Ordinal), item.Name + " explains the edge policy");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response("{\"title\":42,\"detail\":[]}", "application/problem+json", HttpStatusCode.Unauthorized)))))
{
    Check((await client.CheckForUpdateAsync()).Error is not null, "wrong problem field types do not throw");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
{
    Content = new StreamContent(new NonSeekableStream(new MemoryStream(Encoding.UTF8.GetBytes(new string(' ', 300000) + payload))))
    { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } }
}))))
{
    Check((await client.CheckForUpdateAsync()).Error is not null, "chunked oversized JSON is bounded");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
{
    Content = new StreamContent(new StalledStream()) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } }
}))))
using (var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150)))
{
    Check((await client.CheckForUpdateAsync(cancellation.Token)).Error is not null, "streamed response cancellation is handled");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => throw new IOException("synthetic transport fault"))))
{
    Check((await client.CheckForUpdateAsync()).Error is not null, "transport I/O failure is handled");
    Check(!client.IsUpdateRequired, "failed check leaves no update requirement");
}

// Download path against the fake transport: size, hash and progress contract.
var installer = new byte[256 * 1024];
for (var index = 0; index < installer.Length; index++) installer[index] = (byte)(index * 31 % 251);
var installerHash = Convert.ToHexString(SHA256.HashData(installer)).ToLowerInvariant();
string DownloadJson(string sha256, long size) =>
    UpdateJson(current, $"NovaProtect-Setup-{current}.exe", size, sha256,
        $"/api/releases/current/download?version={current}&sha256={sha256}", "2.2.6", false);

async Task<(UpdateClient Client, ClientUpdateInfo Update)> DownloadClientAsync(string json, Func<HttpResponseMessage> download)
{
    var client = new UpdateClient(endpoint, new FakeHandler((request, _) =>
    {
        if (request.RequestUri?.AbsolutePath.EndsWith("/api/releases/current/download", StringComparison.Ordinal) == true)
            return Task.FromResult(download());
        return Task.FromResult(Response(json));
    }));
    var checkedUpdate = await client.CheckForUpdateAsync();
    Check(checkedUpdate.Error is null && checkedUpdate.Update is not null, "download metadata parses");
    return (client, checkedUpdate.Update!);
}

{
    var (client, update) = await DownloadClientAsync(DownloadJson(installerHash, installer.Length), () => Binary(installer));
    var progress = 0L;
    var downloaded = await client.DownloadUpdateAsync(update, new Progress<long>(value => progress = value));
    Check(downloaded.Download is not null && progress == installer.Length, "installer downloads with byte progress");
    if (downloaded.Download is not null)
    {
        string downloadedHashText;
        await using (var stream = File.OpenRead(downloaded.Download.FilePath))
        {
            downloadedHashText = Convert.ToHexString(await SHA256.HashDataAsync(stream));
        }
        Check(downloadedHashText.Equals(installerHash, StringComparison.OrdinalIgnoreCase), "downloaded installer SHA-256 matches");
        var directory = Path.GetDirectoryName(downloaded.Download.FilePath);
        File.Delete(downloaded.Download.FilePath);
        if (directory is not null && Directory.Exists(directory)) Directory.Delete(directory, true);
    }
    client.Dispose();
}

foreach (var (name, json, download) in new (string Name, string Json, Func<HttpResponseMessage> Download)[]
{
    ("content-length mismatch", DownloadJson(installerHash, installer.Length + 1), () => Binary(installer)),
    ("SHA-256 mismatch", DownloadJson(new string('0', 64), installer.Length), () => Binary(installer)),
    ("truncated chunked body", DownloadJson(installerHash, installer.Length + 16), () => Chunked(installer)),
    ("oversized chunked body", DownloadJson(installerHash, 1024), () => Chunked(installer))
})
{
    var (client, update) = await DownloadClientAsync(json, download);
    var downloaded = await client.DownloadUpdateAsync(update);
    Check(downloaded.Download is null && downloaded.Error is not null, name + " is rejected");
    client.Dispose();
}

// Exercise the real HttpClientHandler path against a loopback website.
using (var tcp = new TcpListener(IPAddress.Loopback, 0))
{
    tcp.Start();
    var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
    tcp.Stop();
    var local = new Uri($"http://127.0.0.1:{port}/");
    using var listener = new HttpListener();
    listener.Prefixes.Add(local.ToString());
    listener.Start();
    var server = Task.Run(async () =>
    {
        for (var index = 0; index < 2; index++)
        {
            var context = await listener.GetContextAsync();
            var body = index == 0 ? payload : "{\"detail\":\"unavailable\"}";
            context.Response.ContentType = "application/json";
            if (index == 1) context.Response.StatusCode = 503;
            var bytes = Encoding.UTF8.GetBytes(body);
            await context.Response.OutputStream.WriteAsync(bytes);
            context.Response.Close();
        }
    });
    using var client = new UpdateClient(local);
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update!.ClientVersion == current, "real transport update metadata");
    Check((await client.CheckForUpdateAsync()).Error is not null, "real transport 503 is reported");
    await server.WaitAsync(TimeSpan.FromSeconds(10));
}

string? Argument(string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

async Task<string> CsrfFromAsync(HttpClient browser, string path)
{
    using var response = await browser.GetAsync(path);
    var html = await response.Content.ReadAsStringAsync();
    var match = Regex.Match(html, "name=\"csrf\"[^>]*value=\"([^\"]+)\"");
    if (!match.Success) throw new InvalidOperationException("CSRF token missing on /" + path);
    return WebUtility.HtmlDecode(match.Groups[1].Value);
}

var siteOption = Array.IndexOf(args, "--site");
if (siteOption >= 0)
{
    if (siteOption + 1 >= args.Length) throw new ArgumentException("--site requires a URL");
    var site = new Uri(args[siteOption + 1]);
    if (!site.IsLoopback) throw new InvalidOperationException("Integration is limited to the local test site.");
    var setupToken = Argument("--setup-token") ?? throw new ArgumentException("--setup-token is required for the PHP install wizard test.");
    var installerOption = Array.IndexOf(args, "--installer");
    if (installerOption < 0 || installerOption + 1 >= args.Length) throw new ArgumentException("--installer is required for the PHP install wizard test.");
    var installerPath = args[installerOption + 1];
    var expectedInstallerName = Path.GetFileName(installerPath);
    var adminPassword = Guid.NewGuid().ToString("N") + "-Aa9!";

    var cookies = new CookieContainer();
    using var browser = new HttpClient(new HttpClientHandler { CookieContainer = cookies, AllowAutoRedirect = false }) { BaseAddress = site };
    using var anonymous = new HttpClient { BaseAddress = site };

    using (var health = await anonymous.GetAsync("health"))
    {
        Check(health.StatusCode == HttpStatusCode.OK && (await health.Content.ReadAsStringAsync()).Contains("Healthy", StringComparison.Ordinal), "PHP health endpoint");
    }

    // Install wizard: the one-time setup token sets the single administrator password.
    using var installGet = await browser.GetAsync("install");
    Check(installGet.StatusCode == HttpStatusCode.OK, "PHP install wizard is reachable");
    var installHtml = await installGet.Content.ReadAsStringAsync();
    var installCsrf = WebUtility.HtmlDecode(
        Regex.Match(installHtml, "name=\"csrf\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
    Check(installCsrf.Length > 0, "PHP install wizard CSRF token");
    using var installPost = await browser.PostAsync("install", new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["csrf"] = installCsrf,
        ["setup_token"] = setupToken,
        ["password"] = adminPassword,
        ["confirm_password"] = adminPassword
    }));
    Check(installPost.StatusCode == HttpStatusCode.Found && installPost.Headers.Location?.ToString() == "/admin", "PHP install wizard completes with an administrator password");

    var adminCsrf = await CsrfFromAsync(browser, "admin");
    using (var admin = await browser.GetAsync("admin"))
    {
        var body = await admin.Content.ReadAsStringAsync();
        Check(admin.StatusCode == HttpStatusCode.OK && body.Contains("客户端发布", StringComparison.Ordinal), "administrator backend is reachable after install");
    }

    using (var logout = await browser.PostAsync("logout", new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["csrf"] = adminCsrf
    })))
    {
        Check(logout.StatusCode == HttpStatusCode.Found, "administrator logout redirects");
    }
    using (var locked = await browser.GetAsync("admin"))
    {
        Check(locked.StatusCode == HttpStatusCode.Found && locked.Headers.Location?.ToString() == "/admin/login", "administrator backend requires sign-in after logout");
    }

    // Administrator sign-in with the password set during install.
    var loginCsrf = await CsrfFromAsync(browser, "admin/login");
    using (var wrong = await browser.PostAsync("admin/login", new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["csrf"] = loginCsrf,
        ["password"] = adminPassword + "wrong"
    })))
    {
        Check(wrong.StatusCode == HttpStatusCode.OK && (await wrong.Content.ReadAsStringAsync()).Contains("口令不正确", StringComparison.Ordinal), "wrong administrator password is rejected");
    }

    using var loginPost = await browser.PostAsync("admin/login", new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["csrf"] = loginCsrf,
        ["password"] = adminPassword
    }));
    Check(loginPost.StatusCode == HttpStatusCode.Found && loginPost.Headers.Location?.ToString() == "/admin", "administrator password sign-in");

    // The public update flow needs no session at all.
    using var client = new UpdateClient(site);
    var update = await client.CheckForUpdateAsync();
    Check(update.Error is null && update.Update is not null, "anonymous update metadata (" + (update.Update?.ClientVersion ?? "none") + ")");
    Check(update.Update is { IsNewer: false }, "published version matches the downgrade gate");
    if (update.Update is not null)
    {
        var progress = 0L;
        var downloaded = await client.DownloadUpdateAsync(update.Update, new Progress<long>(value => progress = value));
        Check(downloaded.Download is not null && progress == update.Update.Size, "anonymous update download and progress");
        if (downloaded.Download is not null)
        {
            byte[] downloadedHash;
            byte[] originalHash;
            await using (var downloadedStream = File.OpenRead(downloaded.Download.FilePath))
            {
                downloadedHash = await SHA256.HashDataAsync(downloadedStream);
            }
            await using (var originalStream = File.OpenRead(installerPath))
            {
                originalHash = await SHA256.HashDataAsync(originalStream);
            }
            Check(downloadedHash.SequenceEqual(originalHash), "anonymous update SHA-256 verification");
            var downloadedDirectory = Path.GetDirectoryName(downloaded.Download.FilePath);
            File.Delete(downloaded.Download.FilePath);
            if (downloadedDirectory is not null && Directory.Exists(downloadedDirectory)) Directory.Delete(downloadedDirectory, true);
        }
    }

    // Installer download is public: no session cookie required.
    using (var anonymousDownload = await anonymous.GetAsync("api/releases/current/download", HttpCompletionOption.ResponseHeadersRead))
    {
        Check(anonymousDownload.IsSuccessStatusCode && anonymousDownload.Content.Headers.ContentDisposition?.FileNameStar == expectedInstallerName, "installer download requires no session");
    }
    await using var expected = File.OpenRead(installerPath);
    var expectedHash = await SHA256.HashDataAsync(expected);
    await using var received = await (await anonymous.GetAsync("api/releases/current/download", HttpCompletionOption.ResponseHeadersRead)).Content.ReadAsStreamAsync();
    var receivedHash = await SHA256.HashDataAsync(received);
    Check(expectedHash.SequenceEqual(receivedHash), "download matches original installer SHA-256");
    var downloadPage = await anonymous.GetStringAsync("download");
    Check(downloadPage.Contains(Convert.ToHexString(expectedHash), StringComparison.OrdinalIgnoreCase), "download page displays actual SHA-256");

    foreach (var path in new[] { "", "install", "download", "client-updates", "privacy", "admin/login", "health", "api/releases/current", "css/site.css", "assets/novaprotect.png", "favicon.ico" })
    {
        using var response = await browser.GetAsync(path);
        Check(response.Headers.CacheControl?.NoStore == true &&
              response.Headers.TryGetValues("CDN-Cache-Control", out var cdn) && cdn.Contains("no-store") &&
              response.Headers.TryGetValues("Surrogate-Control", out var proxy) && proxy.Contains("no-store") &&
              response.Headers.Vary.Contains("Cookie"), "no-store response: /" + path);
    }
}
Console.WriteLine($"UPDATE-SMOKE-OK ({passed} checks, version {ProductInfo.Version})");

sealed class FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
}

sealed class NonSeekableStream(Stream inner) : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
}

sealed class StalledStream : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await Task.Delay(Timeout.Infinite, cancellationToken);
        return 0;
    }
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
