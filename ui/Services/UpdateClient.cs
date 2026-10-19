using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NovaProtect.UI.Services;

public sealed record ClientUpdateInfo(
    string ClientVersion,
    string WebsiteVersion,
    string FileName,
    long Size,
    string Sha256,
    Uri DownloadUri,
    string MinimumClientVersion,
    bool ForceUpdate,
    string ReleaseNotes,
    string? PublishedAt,
    bool IsNewer,
    bool IsRequired);

public sealed record ClientUpdateResult(ClientUpdateInfo? Update, string? Error);

public sealed record DownloadedUpdate(string FilePath, ClientUpdateInfo Update);

public sealed record UpdateDownloadResult(DownloadedUpdate? Download, string? Error);

/// <summary>
/// The website has no user accounts or memberships. This client only checks
/// the public release endpoint and downloads the published installer.
/// </summary>
public sealed class UpdateClient : IDisposable
{
    private const int MaxJsonResponseBytes = 256 * 1024;
    private const long MaxUpdateBytes = 1024L * 1024L * 1024L;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(10);
    private static readonly Lazy<UpdateClient> Lazy = new(() => new UpdateClient());
    private static readonly Regex VersionPattern = new(@"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex InstallerPattern = new(@"^NovaProtect-Setup-(\d+\.\d+\.\d+)\.exe$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private readonly HttpClient _http;
    private readonly object _stateGate = new();
    private bool _updateRequired;

    public event EventHandler? StateChanged;

    private UpdateClient()
        : this(new Uri(Models.ProductInfo.WebsiteUrl, UriKind.Absolute))
    {
    }

    // Tests compile this same source and can target a loopback website or inject
    // transport faults. The application only uses Shared and its fixed HTTPS URL.
    internal UpdateClient(Uri baseAddress, HttpMessageHandler? handler = null)
    {
        if (!baseAddress.IsAbsoluteUri || (!string.Equals(baseAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) && !baseAddress.IsLoopback))
            throw new ArgumentException("更新服务地址必须是 HTTPS，测试时允许回环地址。", nameof(baseAddress));

        _http = new HttpClient(handler ?? new HttpClientHandler
        {
            UseCookies = true,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All
        })
        {
            BaseAddress = baseAddress,
            // An explicit CTS below covers headers and streamed response bodies.
            Timeout = Timeout.InfiniteTimeSpan
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"NovaProtect/{Models.ProductInfo.Version}");
        // CDNfly may use this only as a routing hint for native API traffic.
        _http.DefaultRequestHeaders.TryAddWithoutValidation("X-NovaProtect-Client", "1");
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _http.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
    }

    public static UpdateClient Shared => Lazy.Value;

    public bool IsUpdateRequired
    {
        get { lock (_stateGate) return _updateRequired; }
    }

    public void SetUpdateRequired(bool required)
    {
        var changed = false;
        lock (_stateGate)
        {
            changed = _updateRequired != required;
            _updateRequired = required;
        }
        if (changed) StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task<ClientUpdateResult> CheckForUpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CreateTimeout(cancellationToken, RequestTimeout);
            using var request = new HttpRequestMessage(HttpMethod.Get, "api/releases/current");
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                var problem = await ReadProblemAsync(response, timeout.Token);
                return new ClientUpdateResult(null, problem.Message ?? EdgeResponseMessage(response) ?? "当前版本暂时无法读取。");
            }

            var root = await ReadJsonObjectAsync(response, timeout.Token);
            ClientUpdateInfo? update = null;
            string? error = null;
            if (root is null || !TryParseUpdate(root.Value, _http.BaseAddress!, out update, out error))
                return new ClientUpdateResult(null, error ?? "官网返回了无法识别的更新信息。");
            SetUpdateRequired(update!.IsRequired);
            return new ClientUpdateResult(update, null);
        }
        catch (Exception ex) when (IsTransient(ex))
        {
            return new ClientUpdateResult(null, "官网暂时无法连接。");
        }
    }

    public async Task<UpdateDownloadResult> DownloadUpdateAsync(
        ClientUpdateInfo update, IProgress<long>? progress = null, CancellationToken cancellationToken = default)
    {
        if (!TryValidateUpdate(update, _http.BaseAddress!, out var error)) return new UpdateDownloadResult(null, error);

        string? temporaryDirectory = null;
        try
        {
            using var timeout = CreateTimeout(cancellationToken, DownloadTimeout);
            using var request = new HttpRequestMessage(HttpMethod.Get, update.DownloadUri);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                var problem = await ReadProblemAsync(response, timeout.Token);
                return new UpdateDownloadResult(null, problem.Message ?? EdgeResponseMessage(response) ?? "更新文件暂时无法下载。");
            }
            if (response.Content.Headers.ContentLength is long length && length != update.Size)
                return new UpdateDownloadResult(null, "更新文件大小与发布信息不一致。");

            temporaryDirectory = Path.Combine(Path.GetTempPath(), "NovaProtect", "updates", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temporaryDirectory);
            var path = Path.Combine(temporaryDirectory, update.FileName);
            await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 64, FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1024 * 1024];
            long total = 0;
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(), timeout.Token);
                if (read == 0) break;
                total += read;
                if (total > update.Size || total > MaxUpdateBytes) throw new InvalidDataException("更新文件超过声明大小。");
                hash.AppendData(buffer, 0, read);
                await file.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
                progress?.Report(total);
            }

            if (total != update.Size) throw new InvalidDataException("更新文件下载不完整。");
            var actual = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), Convert.FromHexString(update.Sha256)))
                throw new InvalidDataException("更新文件 SHA-256 校验失败。");

            return new UpdateDownloadResult(new DownloadedUpdate(path, update), null);
        }
        catch (Exception ex) when (IsTransient(ex) || ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            if (temporaryDirectory is not null) TryDeleteDirectory(temporaryDirectory);
            return new UpdateDownloadResult(null, ex is OperationCanceledException ? "更新下载已取消。" : ex.Message);
        }
    }

    private async Task<(string? Message, string? Code)> ReadProblemAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var root = await ReadJsonObjectAsync(response, cancellationToken);
        if (root is null) return (null, null);
        return (ReadString(root.Value, "detail") ?? ReadString(root.Value, "title"), ReadString(root.Value, "code"));
    }

    private static string? EdgeResponseMessage(HttpResponseMessage response)
    {
        if ((int)response.StatusCode == 444)
            return "CDNfly 边缘防护拦截了请求（444）。请对 /api/ 和 /download 配置最高优先级放行并关闭 JS/CC 验证。";

        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (response.IsSuccessStatusCode && string.Equals(mediaType, "text/html", StringComparison.OrdinalIgnoreCase))
            return "CDNfly 返回了人机验证页面，更新接口尚未放行。请对 /api/ 配置旁路验证。";

        return null;
    }

    private static async Task<JsonElement?> ReadJsonObjectAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (response.Content.Headers.ContentLength > MaxJsonResponseBytes) return null;

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(chunk.AsMemory(), cancellationToken)) > 0)
        {
            if (buffer.Length + read > MaxJsonResponseBytes) return null;
            buffer.Write(chunk, 0, read);
        }

        try
        {
            var bytes = buffer.GetBuffer().AsMemory(0, checked((int)buffer.Length));
            if (bytes.Span.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) bytes = bytes[3..];
            var isJsonMediaType = mediaType is not null && (mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase) || mediaType.EndsWith("+json", StringComparison.OrdinalIgnoreCase));
            var first = (byte) 0;
            foreach (var value in bytes.Span)
            {
                if (!char.IsWhiteSpace((char) value)) { first = value; break; }
            }
            if (!isJsonMediaType && first != (byte) '{') return null;
            using var document = JsonDocument.Parse(bytes);
            return document.RootElement.ValueKind == JsonValueKind.Object ? document.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool TryParseUpdate(JsonElement root, Uri baseAddress, out ClientUpdateInfo? update, out string? error)
    {
        update = null;
        error = null;
        var clientVersion = ReadString(root, "clientVersion");
        var websiteVersion = ReadString(root, "websiteVersion");
        var fileName = ReadString(root, "fileName");
        var sha256 = ReadString(root, "sha256")?.ToLowerInvariant();
        var downloadPath = ReadString(root, "downloadPath");
        var minimumClientVersion = ReadString(root, "minimumClientVersion") ?? clientVersion;
        var releaseNotes = ReadString(root, "releaseNotes") ?? string.Empty;
        var publishedAt = ReadString(root, "publishedAt");
        var forceUpdate = false;
        if (root.TryGetProperty("forceUpdate", out var forceValue) && forceValue.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        { error = "更新强制策略格式无效。"; return false; }
        if (forceValue.ValueKind is JsonValueKind.True or JsonValueKind.False) forceUpdate = forceValue.GetBoolean();
        if (clientVersion is null || websiteVersion is null || fileName is null || sha256 is null || downloadPath is null || !TryReadInt64(root, "size", out var size))
        { error = "更新信息字段不完整。"; return false; }
        var fileMatch = InstallerPattern.Match(fileName);
        if (!VersionPattern.IsMatch(clientVersion!) || !VersionPattern.IsMatch(websiteVersion!) || !VersionPattern.IsMatch(minimumClientVersion!) || !fileMatch.Success ||
            !string.Equals(fileMatch.Groups[1].Value, clientVersion, StringComparison.Ordinal) ||
            !Regex.IsMatch(sha256!, "^[a-f0-9]{64}$", RegexOptions.CultureInvariant) || size < 1 || size > MaxUpdateBytes ||
            releaseNotes.Length > 12000 || publishedAt?.Length > 128)
        { error = "更新信息格式无效。"; return false; }
        if (!Uri.TryCreate(downloadPath, UriKind.RelativeOrAbsolute, out var relative)) { error = "更新下载地址无效。"; return false; }
        var resolved = new Uri(baseAddress, relative);
        if (!string.Equals(resolved.Scheme, baseAddress.Scheme, StringComparison.OrdinalIgnoreCase) || !string.Equals(resolved.Host, baseAddress.Host, StringComparison.OrdinalIgnoreCase) || resolved.Port != baseAddress.Port || resolved.AbsolutePath != "/api/releases/current/download")
        { error = "更新下载地址不属于 NovaProtect 官网。"; return false; }
        if (!string.Equals(QueryValue(resolved, "version"), clientVersion, StringComparison.Ordinal) || !string.Equals(QueryValue(resolved, "sha256"), sha256, StringComparison.OrdinalIgnoreCase))
        { error = "更新下载地址校验失败。"; return false; }
        if (!Version.TryParse(clientVersion, out var remote) || !Version.TryParse(minimumClientVersion, out var minimum) || !Version.TryParse(Models.ProductInfo.Version, out var current) || minimum > remote)
        { error = "当前版本号无效。"; return false; }
        var isNewer = remote > current;
        update = new ClientUpdateInfo(clientVersion, websiteVersion, fileName, size, sha256, resolved, minimumClientVersion, forceUpdate, releaseNotes, publishedAt, isNewer, isNewer && (forceUpdate || current < minimum));
        return true;
    }

    private static bool TryValidateUpdate(ClientUpdateInfo update, Uri baseAddress, out string? error)
    {
        error = null;
        var fileMatch = InstallerPattern.Match(update.FileName);
        if (!VersionPattern.IsMatch(update.ClientVersion) || !VersionPattern.IsMatch(update.MinimumClientVersion) || !fileMatch.Success || !string.Equals(fileMatch.Groups[1].Value, update.ClientVersion, StringComparison.Ordinal) ||
            !Regex.IsMatch(update.Sha256, "^[a-f0-9]{64}$", RegexOptions.CultureInvariant) || update.Size < 1 || update.Size > MaxUpdateBytes ||
            update.ReleaseNotes.Length > 12000 || update.PublishedAt?.Length > 128 ||
            !update.DownloadUri.IsAbsoluteUri || !string.Equals(update.DownloadUri.Scheme, baseAddress.Scheme, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(update.DownloadUri.Host, baseAddress.Host, StringComparison.OrdinalIgnoreCase) || update.DownloadUri.Port != baseAddress.Port ||
            update.DownloadUri.AbsolutePath != "/api/releases/current/download")
        { error = "更新信息校验失败。"; return false; }
        if (!Version.TryParse(update.ClientVersion, out var remote) || !Version.TryParse(update.MinimumClientVersion, out var minimum) || minimum > remote)
        { error = "更新版本策略无效。"; return false; }
        return true;
    }

    private static string? QueryValue(Uri uri, string name)
    {
        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            var key = separator < 0 ? part : part[..separator];
            if (!string.Equals(Uri.UnescapeDataString(key), name, StringComparison.Ordinal)) continue;
            var value = separator < 0 ? string.Empty : part[(separator + 1)..];
            return Uri.UnescapeDataString(value.Replace('+', ' '));
        }
        return null;
    }

    private static string? ReadString(JsonElement root, string name) => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static bool TryReadInt64(JsonElement root, string name, out long value) { value = 0; return root.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.Number && item.TryGetInt64(out value); }
    private static bool IsTransient(Exception exception) => exception is HttpRequestException or OperationCanceledException or IOException;
    private static CancellationTokenSource CreateTimeout(CancellationToken cancellationToken, TimeSpan duration) { var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(duration); return timeout; }
    private static void TryDeleteDirectory(string directory) { try { if (Directory.Exists(directory)) Directory.Delete(directory, true); } catch { } }

    public void Dispose() => _http.Dispose();
}
