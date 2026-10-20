using System.Text.Json.Serialization;

namespace NovaProtect.UI.Models;

public enum ProtectionMode
{
    Mutation,
    Virtualization,
    Ultra
}

public enum ProtectionTargetArchitecture
{
    Unknown,
    X86,
    X64,
    Arm64
}

public enum MarkerProtectionMode
{
    Inherit,
    Skip,
    Virtualization,
    Ultra
}

public enum CapabilityState
{
    Supported,
    Partial,
    Unsupported,
    Conflict
}

public enum ExecutableToolchain
{
    Unknown,
    Cpp,
    DotNet,
    Rust,
    Go
}

public sealed class ProtectionObjectRule
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Source { get; set; } = ProductInfo.MarkerSource;
    public string DetectorVersion { get; set; } = ProductInfo.MarkerDetectorVersion;
    public uint MarkerRva { get; set; }
    public uint StartRva { get; set; }
    public uint EndRva { get; set; }
    public MarkerProtectionMode Mode { get; set; } = MarkerProtectionMode.Inherit;
    public int VmComplexity { get; set; } = 6;
    public int MutationStrength { get; set; } = 2;
    public bool LockToActivation { get; set; }

    [JsonIgnore]
    public uint Size => EndRva > StartRva ? EndRva - StartRva : 0;

    [JsonIgnore]
    public string AddressRange => $"0x{StartRva:X8} – 0x{EndRva:X8}";

    [JsonIgnore]
    public string Summary => $"{Name} · {AddressRange} · {Size} 字节";

    [JsonIgnore]
    public string Provenance => $"{Source} · {DetectorVersion}";
}

public sealed class ProtectionOptions
{
    public string InputPath { get; set; } = string.Empty;
    public string OutputPath { get; set; } = string.Empty;
    public ProtectionMode Mode { get; set; } = ProtectionMode.Ultra;
    public int MutationStrength { get; set; } = 2;
    public int VmComplexity { get; set; } = 6;
    public int AntiDebugLevel { get; set; } = 2;
    public int AntiVmLevel { get; set; }
    public bool MemoryProtection { get; set; }
    public bool SandboxGuard { get; set; }
    public bool AntiDump { get; set; }
    public bool EnvCheck { get; set; }
    public bool ImportProtection { get; set; }
    public bool ResourceProtection { get; set; }
    public bool PackSections { get; set; } = true;
    public bool EncryptSections { get; set; } = true;
    public bool StripDebugInfo { get; set; } = true;
    public bool StripRelocations { get; set; }
    public bool StripExports { get; set; }
    public string Watermark { get; set; } = string.Empty;
    public string LicenseKey { get; set; } = string.Empty;
    public string ActivationBinding { get; set; } = string.Empty;
    public List<string> VirtualFiles { get; set; } = [];
    public List<ProtectionObjectRule> ObjectRules { get; set; } = [];
}

public sealed class ProtectionProject
{
    public int SchemaVersion { get; set; } = ProductInfo.ProjectSchemaVersion;
    public string Product { get; set; } = ProductInfo.Name;
    public string ProductVersion { get; set; } = ProductInfo.Version;
    public DateTimeOffset SavedAt { get; set; } = DateTimeOffset.Now;
    public ProtectionOptions Options { get; set; } = new();
}

public sealed class BuildPlan
{
    public int SchemaVersion { get; set; } = ProductInfo.BuildPlanSchemaVersion;
    public string PlanId { get; set; } = Guid.NewGuid().ToString("N");
    public string Stage { get; set; } = "draft";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset? PersistedAt { get; set; }
    public string InputPath { get; set; } = string.Empty;
    public string OutputPath { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string Toolchain { get; set; } = string.Empty;
    public List<string> Requested { get; set; } = [];
    public List<string> Effective { get; set; } = [];
    public List<string> Skipped { get; set; } = [];
    public List<string> Conflicts { get; set; } = [];
    public List<ProtectionObjectRule> ObjectRules { get; set; } = [];
    public string? Result { get; set; }
    public int? ExitCode { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }

    [JsonIgnore]
    public bool HasBlockingConflicts => Conflicts.Count > 0;

    [JsonIgnore]
    public string Summary =>
        $"requested: {Join(Requested)}。effective: {Join(Effective)}。" +
        $"skipped: {Join(Skipped)}。conflicts: {Join(Conflicts)}。";

    private static string Join(List<string> values) => values.Count == 0 ? "无" : string.Join("、", values);
}

public sealed record CapabilityCell(string Name, CapabilityState State, string Detail);

public sealed record ArchitectureCapabilityRow(
    string Capability,
    string X86,
    string X64,
    string Arm64,
    string DotNet,
    string Detail);

public sealed record PeSummary(
    bool IsValid,
    ProtectionTargetArchitecture TargetArchitecture,
    string Architecture,
    string Kind,
    bool IsManaged,
    bool IsDll,
    ExecutableToolchain Toolchain,
    string ToolchainDisplay,
    long Size,
    string Detail,
    IReadOnlyList<ProtectionObjectRule> Markers);

public sealed record ProtectionRunResult(bool Success, int ExitCode, string Summary);

public sealed record ActivityItem(DateTimeOffset Time, string Title, string Detail, bool Success);

public static class ProductInfo
{
    public const string Name = "NovaProtect";
    public const string WebsiteUrl = "https://nova.fbi.plus";
    public static string Version { get; } = ResolveVersion();
    public const int ProjectSchemaVersion = 2;
    public const int BuildPlanSchemaVersion = 2;
    public const string MarkerSource = "NovaProtect SDK marker";
    public const string MarkerDetectorVersion = "novaprotect-sdk-marker-v1";

    private static string ResolveVersion()
    {
        var version = typeof(ProductInfo).Assembly.GetName().Version;
        return version is null ? "0.0.0" : $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
    }
}

