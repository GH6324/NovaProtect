using System.Security.Cryptography;
using System.Text;
using System.Runtime.CompilerServices;
using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

internal static class ClientIntegrity
{
    private static readonly List<FileStream> VerifiedFiles = [];
    private static bool _verified;

    [ModuleInitializer]
    internal static void InitializeModule() => EnsureVerified();

    internal static void EnsureVerified()
    {
        lock (VerifiedFiles)
        {
            if (_verified) return;
            try
            {
                var root = AppContext.BaseDirectory;
                var path = Path.Combine(root, "client-integrity.manifest");
                if (new FileInfo(path).Length > 1024 * 1024) throw new InvalidDataException("Manifest size");
                var bytes = File.ReadAllBytes(path);
                var signature = File.ReadAllBytes(Path.Combine(root, "client-integrity.sig"));
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters {
                    Modulus = Convert.FromBase64String(ClientTrustKey.Modulus),
                    Exponent = Convert.FromBase64String(ClientTrustKey.Exponent)
                });
                if (!rsa.VerifyData(bytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    throw new InvalidDataException("Manifest signature");
                var rows = Encoding.UTF8.GetString(bytes).Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (rows.Length < 3 || rows[0] != "NOVAPROTECT-CLIENT-1" || rows[1] != ProductInfo.Version)
                    throw new InvalidDataException("Manifest version");
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var row in rows.Skip(2))
                {
                    if (row.Length < 67 || row.Substring(64, 2) != "  ") throw new InvalidDataException("Manifest row");
                    var relative = row[66..];
                    if (relative.Contains("..", StringComparison.Ordinal) || relative.Contains(':') ||
                        Path.IsPathRooted(relative) || !seen.Add(relative)) throw new InvalidDataException("Manifest path");
                    var file = Path.GetFullPath(Path.Combine(root, relative));
                    if (!file.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Manifest boundary");
                    var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
                    VerifiedFiles.Add(stream); // Hold against modification/deletion for this UI lifetime.
                    if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(stream), Convert.FromHexString(row[..64])))
                        throw new InvalidDataException("Component integrity");
                }
                foreach (var file in new[] { "NovaProtect.exe", "NovaProtect.dll", "NovaProtect.Engine.exe", "NovaProtect.ManagedHost.exe" })
                    if (!seen.Contains(file)) throw new InvalidDataException("Required component");
                if (!string.Equals(Environment.ProcessPath, Path.Combine(root, "NovaProtect.exe"), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Unsupported host");
                _verified = true;
            }
            catch (Exception ex)
            {
                Environment.FailFast("NovaProtect component integrity verification failed.", ex);
            }
        }
    }
}
