using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

public static class ProtectionPlanner
{
    public static BuildPlan Create(ProtectionOptions options, PeSummary? target)
    {
        var plan = new BuildPlan
        {
            InputPath = options.InputPath,
            OutputPath = options.OutputPath,
            Architecture = target?.Architecture ?? "未知",
            Kind = target?.Kind ?? "未知",
            Toolchain = target?.ToolchainDisplay ?? "未知 PE 工具链",
            ObjectRules = options.ObjectRules.Select(CloneRule).ToList()
        };

        var nativeX64 = target is { IsValid: true, TargetArchitecture: ProtectionTargetArchitecture.X64, IsManaged: false };
        var nativeX86 = target is { IsValid: true, TargetArchitecture: ProtectionTargetArchitecture.X86, IsManaged: false };
        var managedExe = target is { IsValid: true, IsManaged: true, IsDll: false,
            TargetArchitecture: ProtectionTargetArchitecture.X64 or ProtectionTargetArchitecture.X86 };
        var supportedPe = nativeX64 || nativeX86 || managedExe;
        var vmRequested = (options.Mode is ProtectionMode.Virtualization or ProtectionMode.Ultra) && options.VmComplexity > 0;
        var mutationRequested = (options.Mode is ProtectionMode.Mutation or ProtectionMode.Ultra) && options.MutationStrength > 0;

        AddRequest(plan, options.PackSections, "区段打包");
        AddRequest(plan, options.EncryptSections, "区段加密");
        AddRequest(plan, vmRequested, $"marker VM {options.VmComplexity}");
        AddRequest(plan, mutationRequested, $"marker 变异 {options.MutationStrength}");
        AddRequest(plan, options.ImportProtection, "导入虚拟化");
        AddRequest(plan, options.ResourceProtection, "资源保护");
        AddRequest(plan, options.MemoryProtection, "内存完整性");
        AddRequest(plan, options.AntiDebugLevel > 0, $"反调试 {options.AntiDebugLevel}");
        AddRequest(plan, options.AntiVmLevel > 0, $"环境检查 {options.AntiVmLevel}");
        AddRequest(plan, options.StripDebugInfo, "调试目录裁剪");
        AddRequest(plan, options.StripRelocations, "重定位裁剪");
        AddRequest(plan, options.StripExports, "导出裁剪");
        AddRequest(plan, !string.IsNullOrWhiteSpace(options.LicenseKey), "运行时许可");
        AddRequest(plan, !string.IsNullOrWhiteSpace(options.ActivationBinding), "激活/硬件绑定");

        if (target is null || !target.IsValid)
        {
            plan.Conflicts.Add("尚未选择有效 PE 目标");
            return plan;
        }

        if (target.TargetArchitecture == ProtectionTargetArchitecture.Arm64)
        {
            plan.Conflicts.Add("当前保护核心没有 ARM64 loader；拒绝生成伪兼容输出");
            return plan;
        }

        if (target.IsManaged && target.IsDll)
        {
            plan.Conflicts.Add("当前版本只接受 C#/VB .NET EXE；托管 DLL 不进入 EXE 保护封装流程");
            return plan;
        }

        if (!supportedPe)
        {
            plan.Conflicts.Add("当前保护核心只接受 x86/x64 EXE（C/C++、C#/VB .NET、Rust、Golang）");
            return plan;
        }

        if (managedExe)
        {
            AddEffective(plan, options.PackSections || options.EncryptSections, ".NET EXE CLR 安全封装");
            AddEffective(plan, options.EncryptSections, "托管载荷加密");
            AddEffective(plan, options.MemoryProtection, "封装载荷完整性");
            AddEffective(plan, options.AntiDebugLevel > 0, $"启动器反调试 {options.AntiDebugLevel}");
            AddEffective(plan, options.AntiVmLevel > 0, $"启动器环境检查 {options.AntiVmLevel}");
            if (options.ImportProtection) plan.Skipped.Add("导入虚拟化（CLR 启动契约必须保留）");
            if (options.ResourceProtection) plan.Skipped.Add("资源保护（托管资源保持在封装载荷中）");
            if (options.StripDebugInfo) plan.Skipped.Add("调试目录裁剪（不重写托管 PE）");
            if (options.StripRelocations) plan.Skipped.Add("重定位裁剪（CLR 封装模式不修改原 PE）");
            if (options.StripExports) plan.Skipped.Add("导出裁剪（CLR 封装模式不修改原 PE）");
            if (vmRequested || mutationRequested) plan.Skipped.Add("marker VM/变异（仅原生 x64 NovaProtect SDK marker）");
            if (!string.IsNullOrWhiteSpace(options.LicenseKey)) plan.Skipped.Add("运行时许可（CLR 封装启动器尚未接入许可解释器）");
            if (!string.IsNullOrWhiteSpace(options.ActivationBinding)) plan.Skipped.Add("激活/硬件绑定（CLR 封装启动器尚未接入）");
            return plan;
        }

        AddEffective(plan, options.PackSections, "区段打包");
        AddEffective(plan, options.PackSections && options.EncryptSections, "区段加密");
        if (options.EncryptSections && !options.PackSections)
            plan.Skipped.Add("区段加密（需要启用区段打包）");

        AddEffective(plan, options.ImportProtection, "导入虚拟化（运行时 IAT 重建）");
        AddEffective(plan, options.ResourceProtection, "资源保护");
        AddEffective(plan, options.StripDebugInfo, "调试目录裁剪");
        if (options.StripExports)
        {
            if (target.IsDll) plan.Conflicts.Add("DLL 导出裁剪会移除对外入口，当前目标是 DLL");
            else plan.Effective.Add("导出裁剪");
        }
        if (options.StripRelocations)
        {
            if (target.IsDll) plan.Conflicts.Add("DLL 不能可靠固定到首选基址，禁止裁剪重定位");
            else plan.Effective.Add("重定位裁剪并关闭 ASLR");
        }

        if (nativeX64)
        {
            AddEffective(plan, options.MemoryProtection, "内存完整性");
            AddEffective(plan, options.AntiDebugLevel > 0, $"反调试 {options.AntiDebugLevel}");
            AddEffective(plan, options.AntiVmLevel > 0, $"环境检查 {options.AntiVmLevel}");
            AddEffective(plan, !string.IsNullOrWhiteSpace(options.LicenseKey), "运行时许可");
            AddEffective(plan, !string.IsNullOrWhiteSpace(options.ActivationBinding), "激活/硬件绑定");

            if (vmRequested || mutationRequested)
            {
                if (target.Markers.Count == 0)
                {
                    plan.Skipped.Add("函数/区域保护（目标中没有 NovaProtect SDK marker）");
                }
                else
                {
                    var selectedMarkers = target.Markers.Count(marker =>
                    {
                        var rule = options.ObjectRules.FirstOrDefault(candidate =>
                            candidate.StartRva == marker.StartRva && candidate.EndRva == marker.EndRva);
                        return rule?.Mode != MarkerProtectionMode.Skip;
                    });
                    if (vmRequested && selectedMarkers > 0) plan.Effective.Add($"{selectedMarkers} 个 marker 区域 VM");
                    if (vmRequested && selectedMarkers == 0) plan.Skipped.Add("marker VM（所有已发现对象均配置为跳过）");
                    if (mutationRequested && vmRequested && selectedMarkers > 0) plan.Effective.Add("VM 前置变异");
                    if (mutationRequested && !vmRequested)
                        plan.Skipped.Add("独立原生变异（当前只实现 VM 前置变异）");
                }
            }
        }
        else
        {
            if (vmRequested) plan.Skipped.Add("marker VM（仅原生 x64）");
            if (mutationRequested) plan.Skipped.Add("marker 变异（仅原生 x64 VM 管线）");
            AddEffective(plan, options.MemoryProtection, "x86 loader 内存完整性");
            if (!string.IsNullOrWhiteSpace(options.LicenseKey)) plan.Conflicts.Add("运行时许可仅支持原生 x64");
            if (!string.IsNullOrWhiteSpace(options.ActivationBinding)) plan.Conflicts.Add("激活/硬件绑定仅支持原生 x64");
            AddEffective(plan, options.AntiDebugLevel > 0, $"x86 loader 反调试 {options.AntiDebugLevel}");
            AddEffective(plan, options.AntiVmLevel > 0, $"x86 loader 环境检查 {options.AntiVmLevel}");
        }

        foreach (var rule in options.ObjectRules)
        {
            if (!string.Equals(rule.Source, ProductInfo.MarkerSource, StringComparison.Ordinal) ||
                !string.Equals(rule.DetectorVersion, ProductInfo.MarkerDetectorVersion, StringComparison.Ordinal))
                plan.Conflicts.Add($"对象规则 {rule.Name} 不是受信任的 NovaProtect SDK marker 来源");
            if (!target.Markers.Any(m => m.StartRva == rule.StartRva && m.EndRva == rule.EndRva))
                plan.Conflicts.Add($"对象规则 {rule.Name} 不匹配当前文件 marker");
            if (rule.Mode is MarkerProtectionMode.Virtualization or MarkerProtectionMode.Ultra && !vmRequested)
                plan.Conflicts.Add($"对象规则 {rule.Name} 请求 VM，但全局模式未启用虚拟化");
            if (rule.LockToActivation && string.IsNullOrWhiteSpace(options.ActivationBinding))
                plan.Conflicts.Add($"对象规则 {rule.Name} 请求激活锁定，但未配置激活绑定");
        }

        if (plan.Effective.Count == 0 && plan.Conflicts.Count == 0)
            plan.Effective.Add("PE 结构重建");
        return plan;
    }

    public static IReadOnlyList<CapabilityCell> MatrixFor(PeSummary? target)
    {
        if (target is null)
            return [new("待识别", CapabilityState.Unsupported, "选择 PE 后显示精确矩阵")];

        return target.TargetArchitecture switch
        {
            ProtectionTargetArchitecture.X64 when !target.IsManaged =>
            [
                new("区段加密", CapabilityState.Supported, "x64 loader 已验证"),
                new("marker VM/Ultra", CapabilityState.Supported, "仅处理 SDK marker 区域"),
                new("导入虚拟化", CapabilityState.Supported, "剥离目录并运行时重建 IAT"),
                new("许可/激活", CapabilityState.Supported, "x64 保护运行时校验"),
                new("重定位裁剪", target.IsDll ? CapabilityState.Conflict : CapabilityState.Partial,
                    target.IsDll ? "DLL 禁止" : "关闭 ASLR，需固定首选基址"),
                new("导出裁剪", target.IsDll ? CapabilityState.Conflict : CapabilityState.Supported,
                    target.IsDll ? "会破坏 DLL 对外入口" : "EXE 可裁剪")
            ],
            ProtectionTargetArchitecture.X86 when !target.IsManaged =>
            [
                new("区段加密", CapabilityState.Supported, "x86 loader 已验证"),
                new("marker VM/Ultra", CapabilityState.Unsupported, "当前 VM 解释器仅 x64"),
                new("导入虚拟化", CapabilityState.Supported, "x86 loader 可重建 IAT"),
                new("许可/激活", CapabilityState.Unsupported, "保护运行时仅 x64"),
                new("重定位裁剪", target.IsDll ? CapabilityState.Conflict : CapabilityState.Partial,
                    target.IsDll ? "DLL 禁止" : "关闭 ASLR，需固定首选基址"),
                new("导出裁剪", target.IsDll ? CapabilityState.Conflict : CapabilityState.Supported,
                    target.IsDll ? "会破坏 DLL 对外入口" : "EXE 可裁剪")
            ],
            ProtectionTargetArchitecture.Arm64 =>
            [new("ARM64", CapabilityState.Unsupported, "尚无 ARM64 loader；当前构建会被拒绝")],
            _ when target.IsManaged && !target.IsDll =>
            [
                new("C#/VB .NET EXE", CapabilityState.Supported, "采用 CLR 安全封装，不修改托管元数据和 IL"),
                new("marker VM/Ultra", CapabilityState.Unsupported, "仅原生 x64 SDK marker"),
                new("导入/重定位/导出裁剪", CapabilityState.Unsupported, "CLR 启动契约保持不变")
            ],
            _ when target.IsManaged =>
            [new(".NET DLL", CapabilityState.Unsupported, "当前版本仅支持 EXE 输入")],
            _ => [new("未知架构", CapabilityState.Unsupported, "当前核心不支持")]
        };
    }

    public static IReadOnlyList<ArchitectureCapabilityRow> FullMatrixFor(PeSummary? target)
    {
        var current = target is null
            ? "尚未选择目标；下表显示当前核心的静态能力边界。"
            : $"当前目标：{target.Architecture} · {target.Kind}；SDK marker {target.Markers.Count} 个。";
        var trimNote = target?.IsDll == true
            ? "当前目标是 DLL：重定位与导出裁剪均为阻断冲突。"
            : "裁剪列描述原生 EXE；DLL 会被规划器和 CLI 阻止。";

        return
        [
            new("PE 识别/检查", "✓", "✓", "只读识别", "只读识别", current),
            new("EXE 输入", "✓ C/C++ · Rust · Go", "✓ C/C++ · Rust · Go", "只读识别", "✓ C#/VB 封装", "语言由 PE/CLR 与构建指纹识别；未知原生工具链按通用原生 PE 处理。"),
            new("区段打包/加密", "✓", "✓", "✕ 无 loader", "✓ CLR 安全封装", "原生 x86/x64 使用 loader；.NET EXE 不重写 CLR 元数据。"),
            new("SDK marker 对象编辑", "✓ 识别/编辑", "✓ 识别/编辑", "✕", "✕", "对象只来自 NovaProtect SDK marker 字节边界，不扫描任意函数。"),
            new("marker VM / Ultra", "✕", "✓", "✕", "✕", "当前 VM translator、descriptor 与 interpreter 仅支持原生 x64。"),
            new("VM 前置变异", "✕", "✓", "✕", "✕", "仅应用于成功翻译的 x64 marker VM 区域。"),
            new("导入虚拟化", "✓", "✓", "✕", "✕", "剥离 loader 可见 Import Directory，并在运行时重建 IAT。"),
            new("内存完整性", "✓ loader", "✓ loader/runtime", "✕", "✕", "x86/x64 均验证恢复后的 region；x64 另有 protection runtime 完整性表。"),
            new("反调试/环境检查", "✓ loader", "✓ loader/runtime", "✕", "✕", "能力按架构走不同运行时路径。"),
            new("运行时许可/激活", "✕", "✓", "✕", "✕", "激活绑定为 x64 进程级前置校验。"),
            new("重定位裁剪", "△ EXE", "△ EXE", "✕", "✕", trimNote),
            new("导出裁剪", "✓ EXE", "✓ EXE", "✕", "✕", trimNote),
            new("项目/构建计划持久化", "✓", "✓", "✓ 配置", "✓ 配置", "不支持构建的目标仍可保存项目和冲突计划，但不会生成伪兼容输出。")
        ];
    }

    private static ProtectionObjectRule CloneRule(ProtectionObjectRule source) => new()
    {
        Id = source.Id,
        Name = source.Name,
        Source = source.Source,
        DetectorVersion = source.DetectorVersion,
        MarkerRva = source.MarkerRva,
        StartRva = source.StartRva,
        EndRva = source.EndRva,
        Mode = source.Mode,
        VmComplexity = source.VmComplexity,
        MutationStrength = source.MutationStrength,
        LockToActivation = source.LockToActivation
    };

    private static void AddRequest(BuildPlan plan, bool enabled, string value)
    {
        if (enabled) plan.Requested.Add(value);
    }

    private static void AddEffective(BuildPlan plan, bool enabled, string value)
    {
        if (enabled) plan.Effective.Add(value);
    }
}

