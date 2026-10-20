<div align="center">

# NovaProtect

**开源的 Windows EXE 代码保护工作台**

致力于让每一个资金短缺的开发者，也能享受到付费级的保护体验。

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20x86%20%7C%20x64-lightgrey)](#)
[![Client](https://img.shields.io/badge/client-v2.2.7-green)](#当前版本)
[![Website](https://img.shields.io/badge/官网-nova.fbi.plus-orange)](https://nova.fbi.plus)

[官网下载](https://nova.fbi.plus) · [更新日志](https://nova.fbi.plus) · [问题反馈](https://github.com/sudfiona/NovaProtect/issues)

</div>

---

> **项目承诺**：本软件不逆向正版的 VMProtect 和 Themida，只摸索思路。永久免费，尽力维护，远程更新端与客户端全部开源，请勿加验证、加壳倒卖。开源不易，且行且珍惜。

---

## 目录

- [项目简介](#项目简介)
- [功能特性](#功能特性)
- [加密与保护原理](#加密与保护原理)
- [支持的目标与能力矩阵](#支持的目标与能力矩阵)
- [软件构成](#软件构成)
- [快速开始](#快速开始)
- [使用说明](#使用说明)
- [NovaProtect SDK](#novaprotect-sdk)
- [项目结构](#项目结构)
- [官网部署](#官网部署)
- [测试与验证](#测试与验证)
- [设计理念](#设计理念)
- [使用须知](#使用须知)
- [许可证](#许可证)

## 项目简介

NovaProtect 将**目标分析、保护配置、关键区域管理和构建输出**整合到统一的 Windows 工作台，帮助开发者为核心算法与业务逻辑配置保护措施。开发者可以根据目标程序的架构、兼容性和运行开销，选择适合项目的保护组合。

NovaProtect 可以处理 C/C++、Rust、Go 等工具链生成的受支持原生 EXE，并为 C#、VB .NET EXE 提供加密封装。实际能力由**文件格式、处理器架构和可处理的代码区域**共同决定——客户端按 PE/CLR 格式真实判定，不按语言标签伪装能力。

产品设计参考了 VMProtect Professional 与 Themida 的组织思路，但围绕自身的 SDK、保护引擎和构建计划实现，不复制也不代表复现相关商业产品的全部功能或保护强度。

## 功能特性

- **多语言目标识别与规划**：支持 C/C++、C#/VB .NET、Rust、Golang EXE 的识别和规划，x86、x64、ARM64、原生 PE 与 .NET 的能力边界在规划前明确展示。
- **真实 SDK 区域管理**：函数/区域对象编辑器只接受目标文件中的真实 NovaProtect SDK marker，不把任意符号、导出或反编译结果伪装成可选函数。
- **配置效果清晰可见**：构建前展示请求项、生效项、跳过项与冲突原因；项目文件和历史快照持久化配置与处理结果，便于持续维护和问题定位。
- **多种保护手段组合**：区段打包加密、x64 关键区域虚拟化、VM 前置代码变异、VM 字节码组合加密、导入保护、运行时完整性校验、许可与机器绑定。
- **图标逐字节保留**：资源区段加密时保留 `RT_ICON`/`RT_GROUP_ICON`，加密后文件在资源管理器中显示的图标与原文件完全一致。
- **可视化客户端**：C# + WinUI 3 界面，提供项目配置、目标检查、保护区域编辑、深浅色主题、构建进度和日志。
- **命令行引擎**：`NovaProtect.Engine.exe` 提供完整命令行参数，方便集成到 CI / 构建脚本。

## 加密与保护原理

NovaProtect 采用分层处理流程：引擎先识别目标程序的结构与能力，再对符合条件的区段、SDK 区域及导入信息应用相应措施，最后生成保护输出与构建记录。

### 原生区段保护

针对符合条件的代码区段以及可选资源区段进行打包；在压缩能够缩小载荷时使用压缩，并在启用区段加密时采用 XOR 编码。程序启动后，由对应架构的加载器恢复载荷。该路径用于改变程序在磁盘上的直接表示形式。

### 关键区域虚拟化与代码变异

针对原生 x64 程序中由 NovaProtect SDK 标记、能够成功翻译的代码区域，将机器指令转换为内部虚拟指令，运行时交由解释器执行。虚拟指令采用映射表编码，Ultra 管线还可在转换前执行代码变异，并对适用字节码追加混淆。这使关键区域的分析需要进一步理解内部指令与执行流程。具体区域能否处理，以指令支持情况、区域空间和构建结果为准。

### VM 字节码组合加密

生成的 VM 字节码采用 RC4、XOR 与字节加法组合处理，并结合区域随机参数及区域位置派生处理参数。运行时按对应顺序恢复字节码，再交给解释器执行。

### 导入保护与运行时校验

原生 x86/x64 导入保护保存导入信息，并由加载器在运行时重建导入地址表（IAT）。根据目标与配置，还可执行载荷或代码区域完整性校验；原生 x64 进一步提供许可数据校验和启动前机器标识绑定。

### 托管程序加密封装

对受支持的 C#、VB .NET EXE，使用基于 XTEA 的载荷加密，由专用宿主完成解密、完整性校验与程序启动。当前方案保留原始 CLR 元数据和 IL 结构，采用封装方式接入原有运行环境（**非 IL 虚拟化**）。

## 支持的目标与能力矩阵

| 目标类型 | 区段或载荷保护 | SDK 区域 VM | 许可与机器绑定 |
| ---------------- | ------- | --------- | ------- |
| 原生 x86 EXE | 区段打包与编码 | 暂不支持 | 暂不支持 |
| 原生 x64 EXE | 区段打包与编码 | 支持适用区域 | 支持 |
| C# 与 VB .NET EXE | 加密封装 | 暂不支持 | 暂不支持 |
| ARM64 | 只读识别 | 暂不支持 | 暂不支持 |

> 原生导入保护覆盖受支持的 x86/x64 目标；.NET 当前提供加密封装，尚未实现 IL 虚拟化；ARM64 暂不生成保护输出。实际可用项目以客户端构建计划和目标程序验证结果为准。

## 软件构成

| 组成部分 | 主要作用 | 主要代码位置 |
| --------- | ------------------------------------ | ---- |
| 可视化客户端 | C# 与 WinUI 3 界面，提供项目配置、区域编辑、构建进度和日志 | `ui/` |
| 原生保护引擎 | C++ 实现 PE 分析、区段处理、虚拟指令转换与输出构建 | `src/`、`include/` |
| 保护运行时 | x86/x64 加载器、x64 解释器与 .NET 专用启动宿主 | `runtime/` |
| SDK 与项目管理 | 标记关键区域，保存区域规则、项目配置和构建快照 | `include/`、`ui/Services/` |
| 官网与用户服务 | 提供客户端下载、更新日志与后台发布 | `website/` |

## 快速开始

### 方式一：下载安装包（推荐）

访问官网 [nova.fbi.plus](https://nova.fbi.plus) 下载最新客户端安装包（`NovaProtect-Setup-<版本>.exe`），无需注册账户，安装包提供 SHA-256 校验值。

当前正式客户端版本：**2.2.7**，安装包 SHA-256：

```
61A219532A81839191ABCA100CB405A5323CA16790BAB2B84C259E806FF687A3
```

### 方式二：从源码构建

#### 环境要求

| 依赖 | 说明 |
| ---- | ---- |
| Windows 10+ x64 | 构建与运行环境 |
| PowerShell | 执行 `build.ps1` 构建脚本 |
| MinGW-w64 | `gcc`、`g++`、`as`、`ld`、`objcopy`、`windres`（脚本默认查找 `C:\mingw\mingw64\bin`） |
| .NET SDK + MSBuild | 构建 WinUI 3 客户端（`net10.0-windows10.0.19041.0`，可通过 Visual Studio 或 `dotnet msbuild`） |
| Inno Setup 6 | 可选，仅打包安装程序时需要 |
| VMProtect SDK | **可选**。未安装时自动以 `NOVAPROTECT_VMP_STUB` 编译为 no-op，开源克隆无需任何 VMProtect 组件即可构建 |

#### 构建步骤

```powershell
git clone https://github.com/sudfiona/NovaProtect.git
cd NovaProtect

# 一键构建全部组件（stub 加载器、保护运行时、变异内核、.NET 宿主、CLI 引擎、WinUI 客户端）
powershell -ExecutionPolicy Bypass -File .\build.ps1 -All

# 也可以按需构建
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Stub -Prot -Mut -Cli -WinUi
```

`build.ps1` 支持的开关：`-Stub`（重编 x86/x64 解压 stub）、`-Prot`（x64 保护运行时）、`-Mut`（变异内核模板）、`-ManagedHost`（.NET 启动宿主）、`-Cli`（`NovaProtect.Engine.exe`）、`-WinUi`（WinUI 3 客户端）、`-All`（全部）。

#### 打包客户端安装程序

```powershell
# 完整流程：版本检查 -> 全量构建 -> Inno Setup 安装包 -> release.json -> 本地 E2E
pwsh -NoProfile -File .\tools\package-client-release.ps1

# 复用已有构建产物、跳过本地站点 E2E
pwsh -NoProfile -File .\tools\package-client-release.ps1 -SkipBuild -SkipE2E

# 打包前先跑回归套件
pwsh -NoProfile -File .\tools\package-client-release.ps1 -RunTests
```

产物为 `artifacts\client-installer\<版本>\NovaProtect-Setup-<版本>.exe`（附 `.sha256`），脚本会同步更新 `website/release.json` 并通过本地 PHP 测试站点完成匿名检查更新、下载与 SHA-256 校验的端到端回归。

## 使用说明

### 可视化客户端

安装后启动 `NovaProtect.exe`，客户端包含四个页面：

- **保护项目**：选择目标文件，调整保护模式（变异 / 虚拟化 / Ultra）与强度参数，后台生成受保护版本；
- **目标检查**：查看 PE/CLR 格式、架构、区段与导入信息，以及架构能力矩阵；
- **活动记录**：构建进度、日志与历史快照；
- **设置**：主题与客户端选项。

内置「兼容、均衡、高强度、Ultra」四档预设，作为配置起点。

### 命令行引擎

`NovaProtect.Engine.exe` 也可直接使用：

```powershell
# 基本用法
NovaProtect.Engine.exe <input.exe> -o output.exe [options]

# 示例：Ultra 模式 + 导入保护 + 反调试
NovaProtect.Engine.exe app.exe -o app_protected.exe -mode ultra -imports -ad 2

# 查看 PE 信息
NovaProtect.Engine.exe app.exe -info
```

常用参数：

| 参数 | 说明 |
| ---- | ---- |
| `-mode <name>` | 保护模式：`mutation` / `virtualization` / `ultra` |
| `-mut <0-3>` | 变异强度 |
| `-vm <0-10>` | VM 复杂度 |
| `-ad <0-3>` / `-avm <0-2>` | 反调试 / 反虚拟机级别 |
| `-memory` / `-imports` / `-resources` | 内存完整性保护 / 导入保护 / 资源区段保护 |
| `-noencrypt` | 打包区域不加密存储 |
| `-nopack` | 禁用打包 |
| `-stripreloc` / `-stripexport` | 移除重定位目录（关闭 ASLR）/ 导出目录（仅 EXE） |
| `-license <key>` / `-activation <id>` | 启用许可校验 / x64 机器标识绑定 |
| `-machineid` | 打印本机激活标识 |
| `-region <spec>` | SDK 区域规则：`start-end-mode-vm-mut-lock` |
| `-watermark <text>` / `-script <file>` / `-vf <file>` | 水印 / 保护脚本 / 内嵌虚拟文件 |
| `-info` / `-showwatermark` / `-listvf` / `-extractvf` | 检查与提取 |

## NovaProtect SDK

在源代码中使用 SDK 标记指定需要虚拟化的关键区域。客户端的**对象编辑器只接受目标文件中真实的 NovaProtect SDK marker**，每条区域规则都会持久化 `Source=NovaProtect SDK marker` 与检测器版本，任意符号名、导出表或反编译结果都不会被当作保护对象。

标记格式（字节特征）：

- **x64**：`48 8D 0D 00 00 00 00` + 20 个 `NOP`
- **x86**：`8D 0D 00 00 00 00` + 20 个 `NOP`，区域终点为后续 20 个 `NOP`

在 C/C++ 中通过兼容的 marker 宏调用（`include/vmp_markers.h`）标记区域：

```cpp
#include "vmp_markers.h"

int critical_algorithm(int a, int b) {
    VMProtectBeginUltra("critical_algorithm");
    // ... 核心算法逻辑，构建时被翻译为虚拟指令 ...
    VMProtectEnd();
    return a * b;
}
```

> 未安装商业 VMProtect SDK 时，这些调用在构建期编译为 no-op（`NOVAPROTECT_VMP_STUB`），不影响开源克隆的构建与运行。

## 项目结构

```
NovaProtect/
├── build.ps1              # 一键构建脚本（MinGW + .NET）
├── VERSION                # 客户端版本号（权威来源）
├── version-lock.json      # 源码封存摘要
├── STATUS.md              # 项目当前状态与验收清单
├── src/                   # C++ 保护引擎（packer、mutation、disasm、vm_engine、
│                          #   anti_debug、managed_envelope、pe_lib 等）
├── include/               # 引擎与 SDK 头文件（vm_isa、mutation、vmp_markers 等）
├── runtime/               # 保护运行时：x86/x64 解压 stub（stub.S / stub32.S）、
│                          #   x64 解释器（prot64.c）、变异内核（mutkern.S）、
│                          #   .NET 启动宿主（managed_host.cpp）
├── ui/                    # WinUI 3 可视化客户端（Pages / Models / Services）
├── installer/             # Inno Setup 安装包脚本（含简体中文语言文件）
├── website/               # PHP 8.4 官网与应用（下载、更新日志、管理后台、部署脚本）
├── tests/                 # 回归测试：regress.ps1、planner-smoke、C++/C#/VB/Rust/Go 样本
├── tools/                 # 构建、打包、验证、调试工具脚本
└── docs/                  # 设计文档、验收报告、保护流程图（mermaid）
```

## 官网部署

官网基于 **PHP 8.4 + PHP-FPM**，适配 Linux 宝塔 Nginx，带浏览器安装向导、客户端下载、更新日志和管理后台（客户端发布上传、离线升级）。网站无用户账户系统，仅一个管理员口令（Argon2id 哈希存储），可通过 SSH 工具 `reset-admin-password.php` 重置。

```bash
# 完整包首次安装（解压 ZIP 后）
bash install.sh --check-package   # 只读校验包布局与 SHA-256
bash install.sh

# 已有站点升级
bash upgrade.sh --check-package
bash upgrade.sh

# 回滚
bash deploy/rollback.sh
```

每次发布同时生成完整安装包与精简升级包，安装/升级流程包含备份、迁移、健康检查与回滚支持。详见 [`website/deploy/README.md`](website/deploy/README.md)。

## 测试与验证

```powershell
# 版本策略检查
pwsh -NoProfile -File .\tools\version.ps1 -Action Check

# 客户端核心回归套件（x64/x86 保护、图标保留等，预期 ALL PASS）
powershell -ExecutionPolicy Bypass -File .\tests\regress.ps1

# 规划器冒烟测试（预期 PLANNER-SMOKE-OK）
dotnet run -c Release --project .\tests\planner-smoke\NovaProtect.PlannerSmoke.csproj -- .

# 网站安装 / 升级 / 发布上传回归（Python）
python -m unittest tests/deploy_config_test.py -v
python tests/client_release_upload_smoke.py
python -B -m unittest tests/website_installer_test.py -v
```

`tests/samples/` 内置 C/C++、C#、VB .NET、Rust、Golang 五种语言样本，均已通过保护与运行验证。

## 设计理念

**保护对象明确。** 区域对象来自目标文件中真实的 NovaProtect SDK 标记。开发者结合代码价值、性能要求和兼容性，确定需要处理的关键区域并设置规则。

**配置与结果可核查。** 构建前展示请求项、生效项、跳过项与冲突原因；历史快照记录项目配置与构建结果，便于后续复用、核查与兼容性定位。

**能力边界诚实。** x86、x64、ARM64、原生 PE 与 .NET 的支持范围在规划前明确展示，不伪装能力。当前明确边界：.NET 为加密封装而非 IL 虚拟化；ARM64 只读识别；原生 x86 暂不支持 VM、许可与机器绑定。

## 使用须知

- 本项目采用 **GPL-3.0** 开源，永久免费，请勿加验证、加壳倒卖。
- 代码保护提高逆向分析成本，但**不能保证绝对安全**；实际保护效果以构建计划和目标程序验证结果为准。
- 请仅用于保护您拥有合法权利的软件，遵守所在地区法律法规，不得用于违法用途。

## 许可证

本项目基于 [GNU General Public License v3.0](LICENSE) 开源发布。

---

<div align="center">

**[官网 nova.fbi.plus](https://nova.fbi.plus)** · 如果这个项目对你有帮助，欢迎点一个 Star ⭐

</div>
