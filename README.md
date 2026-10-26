# NovaProtect

Windows EXE 保护工作台。官网与下载：<https://nova.fbi.plus>

NovaProtect 把目标 PE 中的选定函数/区域翻译成自有指令集并交给内置解释器执行，配合变异、反调试、内存保护与导入混淆，使关键逻辑不以原生形式出现在成品里。

> **本仓库不包含保护引擎源码。** VM 指令集、字节码解释器、二次虚拟化器、加密层与 X64 引导桩属于专有实现，不在本仓库内。这里公开的是**接入层、客户端 UI、官网源码与发布工具**。详见 [`docs/REPOSITORY-SCOPE.md`](docs/REPOSITORY-SCOPE.md)。

## 目录

| 路径 | 内容 |
| --- | --- |
| `sdk/` | 集成头文件与示例：用 `NOVAPROTECT_BEGIN/END` 标记要保护的函数 |
| `ui/` | WinUI 3 客户端（项目编辑器、保护页、构建进度、更新检查） |
| `website/` | 官网源码（PHP 8.4 + 宝塔 Nginx/PHP-FPM），含安装向导与管理后台 |
| `installer/` | Inno Setup 安装器脚本 |
| `tools/` | 发布工具：客户端打包、网站打包、包校验、版本管理 |
| `docs/` | 产品说明、部署文档与验证报告 |

## 快速开始

### 1. 用 SDK 标记函数

```cpp
#include "novaprotect_sdk.h"

int verify_license(const char* key)
{
    NOVAPROTECT_BEGIN("verify_license");
    // 希望被虚拟化的逻辑
    NOVAPROTECT_END();
    return result;
}
```

编译后把 EXE 拖进客户端，选择「虚拟化」或「Ultra」模式。

### 2. 或者用函数扫描（无需改源码）

客户端「保护」页对 x64 目标读取 `.pdata` 异常目录，枚举全部运行时函数（含静态函数），勾选即可对整段函数体做 VM 保护。

### 3. 安装客户端

从官网下载：<https://nova.fbi.plus/download>

当前版本号见 [`VERSION`](VERSION)，安装包名与 SHA-256 记录在 [`website/release.json`](website/release.json)（该文件由发布流程自动写入，是安装包校验值的单一来源）。

## 能力边界

NovaProtect 只处理它**确实能证明**的能力，不用语言标签包装格式支持：

| 目标 | 状态 |
| --- | --- |
| x64 原生 PE | 完整支持（虚拟化、变异、多区域） |
| x86 原生 PE | 支持（不含 x64 虚拟机） |
| .NET / CLR | 安全封装，**不是** IL 虚拟化 |
| ARM64 | 只读识别，不提供保护 |

VM 解释器处理纯寄存器、直线型 x86-64 子集。以下形式会被**安全跳过**（保留原生代码，功能不受影响）：

- 访问 `RSP`/`RBP` 或内存（`[reg+disp]`、RIP 相对寻址）
- 非 `REX.W` 的 32 位操作数形式
- `CALL`/`RET`/`PUSH`/`POP`/`IMUL`/`movabs`、带 index 的 `LEA` 等解释器不支持的指令

需要真正虚拟化关键函数时，使用 `sdk/examples/example_vm.S` 的寄存器直通汇编块。块长需容纳运行时 trampoline（约 `51 + 10×保留寄存器数 + 16` 字节），函数体至少约 137 字节才可能被虚拟化。

## 部署官网

完整包用于首次安装或完整恢复：

```bash
bash install.sh
```

已有站点只用升级包：

```bash
bash upgrade.sh --check-package
bash upgrade.sh
```

详见 [`website/README.md`](website/README.md) 与 [`website/deploy/README.md`](website/deploy/README.md)。忘记管理员口令不需要重装，用 root 执行 `php /www/server/novaprotect/bin/reset-admin-password.php` 按提示重设。

## 发布工具

```powershell
# 客户端：版本检查 -> 全量构建 -> Inno Setup 安装包 -> release.json -> 本地 E2E
pwsh -NoProfile -File .\tools\package-client-release.ps1

# 打包前先跑回归
pwsh -NoProfile -File .\tools\package-client-release.ps1 -RunTests

# 网站：完整包 + 精简升级包，并校验 ZIP 布局与哈希
pwsh -NoProfile -File .\tools\package-website.ps1
pwsh -NoProfile -File .\tools\verify-website-package.ps1

# 生成本公开源码包
pwsh -NoProfile -File .\tools\package-github-source.ps1
```

客户端打包需要 MinGW-w64（`g++`/`gcc`/`ld`/`objcopy`）、Inno Setup 6 或 7、.NET SDK 以及 PHP CLI（用于本地站点 E2E）。**保护引擎源码不在本仓库，因此从本仓库无法构建出完整的保护器**——上述脚本面向拥有完整源码树的维护者。


- `sdk/` 下的头文件可复制进你与 NovaProtect 配合使用的软件中。
- `website/` 源码可供已授权部署的运维者安装与维护自有站点。

## 安全

发现安全问题时请勿提交 issue，或者通过官网联系维护者。
