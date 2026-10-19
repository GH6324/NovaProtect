using System.Text;

namespace NovaProtect.UI.Services;

/// <summary>
/// Keeps a bounded, UTF-8 diagnostic log in the current user's profile.
/// The log never contains account passwords or authentication tokens.
/// </summary>
public static class ClientDiagnosticLog
{
    private const long MaxLogBytes = 10 * 1024 * 1024;
    private static readonly object Gate = new();
    private static string? _path;

    public static string LogPath => _path ??= ResolvePath();

    public static void Initialize()
    {
        Write("INFO", $"Client started; version={Models.ProductInfo.Version}; os={Environment.OSVersion}");
    }

    public static void Info(string message) => Write("INFO", message);

    public static void Error(string message, Exception? exception = null)
    {
        var detail = exception is null ? message : $"{message}: {exception.GetType().Name}: {exception.Message}";
        Write("ERROR", detail);
    }

    public static byte[] ReadRecentBytes(long maxBytes = MaxLogBytes)
    {
        maxBytes = Math.Clamp(maxBytes, 1024, MaxLogBytes);
        try
        {
            lock (Gate)
            {
                var path = LogPath;
                if (!File.Exists(path)) return [];
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var start = Math.Max(0, stream.Length - maxBytes);
                stream.Seek(start, SeekOrigin.Begin);
                var length = checked((int)(stream.Length - start));
                var bytes = new byte[length];
                var offset = 0;
                while (offset < bytes.Length)
                {
                    var read = stream.Read(bytes, offset, bytes.Length - offset);
                    if (read == 0) break;
                    offset += read;
                }
                return offset == bytes.Length ? bytes : bytes[..offset];
            }
        }
        catch
        {
            return [];
        }
    }

    private static void Write(string level, string message)
    {
        try
        {
            lock (Gate)
            {
                var path = LogPath;
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                if (File.Exists(path) && new FileInfo(path).Length > MaxLogBytes)
                {
                    var backup = path + ".1";
                    File.Delete(backup);
                    File.Move(path, backup);
                }

                var safe = message.Replace('\r', ' ').Replace('\n', ' ');
                var line = $"{DateTimeOffset.UtcNow:O} [{level}] {safe}{Environment.NewLine}";
                File.AppendAllText(path, line, new UTF8Encoding(false));
            }
        }
        catch
        {
            // Diagnostics must never break the client.
        }
    }

    private static string ResolvePath()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(root, Models.ProductInfo.Name, "logs", "client.log");
    }
}
