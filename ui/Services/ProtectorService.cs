using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

public sealed partial class ProtectorService
{
    public async Task<ProtectionRunResult> RunAsync(
        ProtectionOptions options,
        Action<int, string> onProgress,
        CancellationToken cancellationToken)
    {
        var cli = Path.Combine(AppContext.BaseDirectory, "NovaProtect.Engine.exe");
        if (!File.Exists(cli))
            return new ProtectionRunResult(false, -1, $"找不到保护核心：{cli}");

        var start = new ProcessStartInfo
        {
            FileName = cli,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        Add(start, options.InputPath);
        Add(start, "-o", options.OutputPath);
        Add(start, "-mode", options.Mode switch
        {
            ProtectionMode.Mutation => "mutation",
            ProtectionMode.Virtualization => "virtualization",
            _ => "ultra"
        });
        Add(start, "-mut", options.MutationStrength.ToString());
        Add(start, "-vm", options.VmComplexity.ToString());
        Add(start, "-ad", options.AntiDebugLevel.ToString());
        Add(start, "-avm", options.AntiVmLevel.ToString());

        Flag(start, options.MemoryProtection, "-memory");
        Flag(start, options.ImportProtection, "-imports");
        Flag(start, options.ResourceProtection, "-resources");
        Flag(start, options.SandboxGuard, "-sandbox-guard");
        Flag(start, options.AntiDump, "-anti-dump");
        Flag(start, options.EnvCheck, "-env-check");
        Flag(start, !options.PackSections, "-nopack");
        Flag(start, !options.EncryptSections, "-noencrypt");
        Flag(start, !options.StripDebugInfo, "-keepdebug");
        Flag(start, options.StripRelocations, "-stripreloc");
        Flag(start, options.StripExports, "-stripexport");
        AddOptional(start, "-watermark", options.Watermark);
        AddOptional(start, "-license", options.LicenseKey);
        AddOptional(start, "-activation", options.ActivationBinding);
        foreach (var rule in options.ObjectRules)
        {
            if (!string.Equals(rule.Source, ProductInfo.MarkerSource, StringComparison.Ordinal) ||
                !string.Equals(rule.DetectorVersion, ProductInfo.MarkerDetectorVersion, StringComparison.Ordinal))
                throw new InvalidOperationException($"对象规则 {rule.Name} 不是由 NovaProtect SDK marker 检测器生成");
            Add(start, "-region", $"{rule.StartRva:X}-{rule.EndRva:X}-{ModeName(rule.Mode)}-{rule.VmComplexity}-{rule.MutationStrength}-{(rule.LockToActivation ? 1 : 0)}");
        }
        foreach (var virtualFile in options.VirtualFiles) Add(start, "-vf", virtualFile);

        using var process = new Process { StartInfo = start, EnableRaisingEvents = true };
        var recent = new Queue<string>();
        var started = false;

        void Handle(string? line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            lock (recent)
            {
                recent.Enqueue(line);
                while (recent.Count > 8) recent.Dequeue();
            }

            var match = ProgressRegex().Match(line);
            var percent = match.Success && int.TryParse(match.Groups[1].Value, out var value) ? value : -1;
            onProgress(percent, line);
        }

        process.OutputDataReceived += (_, e) => Handle(e.Data);
        process.ErrorDataReceived += (_, e) => Handle(e.Data);

        try
        {
            using var invocation = ClientInvocation.Create(start);
            if (!process.Start()) return new ProtectionRunResult(false, -1, "无法启动保护核心");
            started = true;
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await using var registration = cancellationToken.Register(() =>
            {
                try { if (!process.HasExited) process.Kill(true); } catch { }
            });
            await invocation.AuthorizeAsync(process, cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            string summary;
            lock (recent) summary = string.Join(Environment.NewLine, recent);
            return new ProtectionRunResult(process.ExitCode == 0, process.ExitCode, summary);
        }
        catch (OperationCanceledException)
        {
            return new ProtectionRunResult(false, -2, "操作已取消");
        }
        catch (Exception ex)
        {
            if (started)
            {
                try
                {
                    using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await process.WaitForExitAsync(wait.Token);
                }
                catch { }
            }

            string details;
            lock (recent) details = string.Join(Environment.NewLine, recent);
            ClientDiagnosticLog.Error("Protection core invocation failed", ex);
            var summary = string.IsNullOrWhiteSpace(details)
                ? ex.Message
                : $"{ex.Message}{Environment.NewLine}{details}";
            var exitCode = started && process.HasExited ? process.ExitCode : -1;
            return new ProtectionRunResult(false, exitCode, summary);
        }
    }

    public async Task<(bool Success, string Output)> InspectAsync(string path, params string[] command)
    {
        var cli = Path.Combine(AppContext.BaseDirectory, "NovaProtect.Engine.exe");
        var start = new ProcessStartInfo
        {
            FileName = cli,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        if (!string.IsNullOrWhiteSpace(path)) Add(start, path);
        foreach (var item in command) start.ArgumentList.Add(item);
        try
        {
            using var invocation = ClientInvocation.Create(start);
            using var process = Process.Start(start);
            if (process is null) return (false, "无法启动检查工具");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            try { await invocation.AuthorizeAsync(process, CancellationToken.None); }
            catch (Exception ex) { return (false, ex.Message + "\n" + await stdout + await stderr); }
            await process.WaitForExitAsync();
            var output = await stdout + await stderr;
            return (process.ExitCode == 0, output.Trim());
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static void Add(ProcessStartInfo start, params string[] values)
    {
        foreach (var value in values) start.ArgumentList.Add(value);
    }

    private static void AddOptional(ProcessStartInfo start, string name, string value)
    {
        if (!string.IsNullOrWhiteSpace(value)) Add(start, name, value);
    }

    private static void Flag(ProcessStartInfo start, bool enabled, string value)
    {
        if (enabled) start.ArgumentList.Add(value);
    }

    private static string ModeName(MarkerProtectionMode mode) => mode switch
    {
        MarkerProtectionMode.Skip => "skip",
        MarkerProtectionMode.Virtualization => "virtualization",
        MarkerProtectionMode.Ultra => "ultra",
        _ => "inherit"
    };

    [GeneratedRegex(@"^\[\s*(\d{1,3})%\]")]
    private static partial Regex ProgressRegex();
}

