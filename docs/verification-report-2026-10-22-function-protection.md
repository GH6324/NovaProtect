# NovaProtect 2.3.2 手动函数保护验证报告

- 日期：2026-10-22（Asia/Shanghai）
- 工作区：`artifacts/github-source/NovaProtect-2.3.0`
- 范围：VMP 式手动函数保护（扫描 / 勾选 / 添加所有函数）端到端；变异 + 虚拟化组合结果错误修复；发布打包与官网升级
- 状态：全部通过（1 项既有环境限制 FAIL 与改动无关）

## 1. 功能形态

客户端「保护」页在 SDK marker 编辑器之外新增「函数保护（VMP 式扫描）」卡片：

- **扫描**：对 x64 目标解析 PE 头 / 节表 / 数据目录，遍历 `.pdata` 的 `RUNTIME_FUNCTION`
  表枚举全部运行时函数（含静态函数，x86 走导出表 + `push ebp;mov ebp,esp` 序言启发式），
  上限 20000 条；并行读导出表补名称。
- **选择**：列表 CheckBox 双向绑定 + 过滤（全部 / 仅可虚拟化 / 仅导出 / 仅已勾选）+ 全选 /
  反选 / 添加所有函数 / 清除；批量设置模式（inherit / virtualization / ultra / mutation /
  skip）、VM 复杂度、变异强度、激活锁定；项目加载时按 RVA 恢复勾选状态。
- **传参**：函数规则经 `ProtectorService` 以 `-func StartRva-EndRva-Mode-Vm-Mut-Lock` 下发
  （marker 规则仍走 `-region`）；`ProtectionPlanner` 对函数规则独立校验（不要求匹配 marker），
  能力矩阵计入「N 个扫描函数 VM」。

引擎侧：`FunctionSource` 双来源（`SdkMarker=0` marker 边界 / `ScanFunction=1` 函数体范围），
`-func` 与 `-region` 同格式；区域上限统一为 `kMaxVmRegions = 64`（原 packer 写死 32，
runtime `np_vm_install` 实际支持 64）。

## 2. 修复的三个引擎级缺陷（变异 + VM 结果错误）

| # | 缺陷 | 根因 | 修复 |
| --- | --- | --- | --- |
| 1 | `-mode ultra -mut 2` 下 VM 区域结果错误（如 `pure(42)` 得 `576459777346673544` 而非 `826248`），低 32 位正确、高 32 位为垃圾 | `src/disasm.cpp` `parseImmediate` 对 REX.W 指令的 imm32/imm8 不做符号扩展：变异把 `add rax,0x1111` 换成 `sub rax,-0x1111`（`48 81 E8 EF EE FF FF`），VM 拿到零扩展立即数 `0xFFFFEEEF`，`rax-0xFFFFEEEF` 污染高 32 位，后续 `shl/shr` 把垃圾带进结果 | `parseImmediate` 按 REX.W 存在性对 imm8/imm16/imm32 做符号扩展（x86-64 硬件语义） |
| 2 | 含 32 位操作数的函数虚拟化后，入参高 32 位非零时结果错误 | wire VM 是 64 位机：`add eax,imm` 的高 32 位清零与 32 位进位/符号标志无法复现 | `VMTranslator::translate` 增加 `target64` 参数；x64 流中非 REX.W 的寄存器写入/标志类指令终止翻译（packer 传 `pe.is64()`），区域安全保留原生 |
| 3 | 多函数打包后，未保护函数的调用方跨调用保留在 `r9` 的活值被踩（`f2` 的 VM 踩掉 `main` 里 `f3` 的结果） | trampoline 用 `rcx/edx/r8/r9` 传解释器参数、`np_vm_run` 是 C 函数经 `rax` 返回并用 `r10/r11` 做 scratch；保存/恢复只覆盖 guest mask 内的寄存器。编译器（IPA 寄存器分配）合法地把活值放在调用者保存寄存器里跨调用 | packer 对每个 VM 区域强制保留 `rax/rcx/rdx/r8-r11`（`mask |= 0x0F07`）；`rbx/rbp/r12-r15/rdi/rsi` 经验证由 `np_vm_run` 自身保存（反汇编确认 8 个 push/pop） |

定位方法：`tools/vmdbg.cpp` 新调试 harness 复刻 packer 的「变异管线 → 翻译 → 混淆 →
np_vm_run 模拟」全链路，二分出「变异流 34 条全部翻译成功但算错」→ 逐条反汇编对比字节 →
ALUI 跟踪暴露立即数零扩展；多函数问题由 186 函数全保护 E2E 暴露（`f2` 单独打包即踩
`f3`），dump packed PE + 反汇编 `np_vm_run` 确认调用者保存集合。

## 3. 端到端验证矩阵（Observed）

| 场景 | 条件 | 结果 |
| --- | --- | --- |
| 单函数 × 变异强度扫描 | `pure.exe -func 16D0-1760`，`-mut 0/1/2/3`，`-vm 6` | 四档全部 `826248 / 1525640 / 15676424`（与原生逐位一致） |
| 三函数 × 变异 + VM | `multi2.exe` 三条 `-func`，`-mode ultra -vm 6 -mut 2` | `f1/f2/f3` 三输入全部正确；三区域分别虚拟化 81/78/77 条指令 |
| 三函数 × `-mut 3 -noencrypt` | 同上，关闭载荷加密 | 输出与加密路径一致 |
| 单函数打包不影响邻居 | 只保护 `f2` | `f1/f3` 结果不变（回归缺陷 3 的修复确认） |
| 186 函数「添加所有函数」 | `many.exe` 全 `.pdata` 函数，`-mode ultra -vm 6 -mut 2` | 64 个虚拟化、109 个「region table full (64 max)」如实跳过、13 个因栈帧/无函数体/32 位形式跳过；`sum=48113254441943040` 与原生一致 |
| 32 位函数安全回退 | `noFrame32.exe`（无栈帧 32 位算术） | `VM skip region: 32-bit operand form`，程序输出不变 |
| 含栈帧函数安全回退 | `int32.exe`（CRT 栈帧） | `VM skip region: uses RSP/RBP`，程序输出不变 |
| 回归套件 | `tests/regress.ps1`（test-only core，2.3.2 源码重建） | 40 OK / 5 SKIP / 1 FAIL |
| UI 编译 | `dotnet build ui/NovaProtect.UI.csproj -c Release` | 0 警告 0 错误 |

已知环境限制（与本次改动无关，历轮同样存在）：5 个 x86 用例因缺 `tests/hostname32.exe`
（MinGW 无 32 位工具链）SKIP；planner-smoke「x86 detection failed」同因缺该 fixture。

UI 侧同步修正：函数可行性阈值 `MinVirtualizableSize` 80 → 137（trampoline 固定保留 7 个
寄存器：`51 + 10×7 + 16 = 137`），与 packer 实测口径一致。

## 4. 产物

| 文件 | 说明 |
| --- | --- |
| `src/disasm.cpp` | REX.W 立即数符号扩展 |
| `src/vm_engine.cpp` / `include/vm_isa.h` | `target64` 参数 + 32 位操作数门禁 |
| `src/packer.cpp` | trampoline 保留集 `0x0F07`；DBG 诊断行已清除 |
| `ui/Services/FunctionScanner.cs` | 可行性阈值 137；文档注释同步 |
| `sdk/README.md` | 新增「手动添加函数保护」章节与 VM 子集边界 |
| `website/app/site.php` | SDK 页新增函数扫描器说明 |
| `tools/vmdbg.cpp` | 新增 VM 降低调试 harness（复刻 packer 管线） |
| `NovaProtect.Engine.exe` / `NovaProtect.dll` | 全量构建重建（UI 门禁内） |
| `artifacts/test-only-core-2.3.1/CoreRegression.exe` | 回归用测试核心，已重建 |

## 5. 2.3.2 发布打包与官网升级

- 版本：客户端 `2.3.1 → 2.3.2`，官网 `2.2.16 → 2.2.17`（两条版本流独立）。
- 全量构建：prot64 blob 19296 字节（+1056 bss），绝对指针 tripwire 报 0；engine /
  managed host / WinUI 重建；客户端完整性签名 520 文件（RSA-3072/SHA-256，2.3.2）。
- 安装包：`artifacts/client-installer/2.3.2/NovaProtect-Setup-2.3.2.exe`，60,896,852 字节
  （58.1 MB），SHA-256 `3e73ab7c1ca157bf227a33753928672f644ad7d09521cb13e60d222f4555b246`；
  PE 版本资源内嵌描述「新增手动函数保护：VMP 式扫描、勾选与全函数保护」（Inno 30 字符限制内）。
- `website/release.json`：`websiteVersion 2.2.17 / clientVersion 2.3.2 /
  fileName NovaProtect-Setup-2.3.2.exe / sha256 3e73ab7c…`，与安装包实测一致。
- 本地 PHP E2E（`tools/package-client-release.ps1 -SkipBuild`）：`UPDATE-SMOKE-OK`，
  72 项断言全过——安装向导、管理员登录/登出/限速、匿名更新元数据、下载字节进度、
  SHA-256 校验、全页面 no-store 响应头。
- 官网部署包（`tools/package-website.ps1`，内置 verify + `tests/website_installer_test.py`
  24 项 OK / 1 skipped）：
  - `artifacts/website-full/2.2.17/NovaProtect-Website-2.2.17-Linux-x64-BaoTa-Full.zip`，
    60,653,104 字节，SHA-256 `636FCDE44F4F00BDB37E34882E20CC8075D26974050987D1C60C5813F435DCAC`；
  - `artifacts/website-upgrade/2.2.17/NovaProtect-Website-2.2.17-Linux-x64-BaoTa-Upgrade.zip`，
    60,646,237 字节，SHA-256 `D249E6D08F3B944103F27854CC3D46BDDD7A01BB6F2BAAA72F8EB16CE6675DAB`。
- GitHub 源码包：`artifacts/github-source/NovaProtect-2.3.2-source.zip`，238 文件、
  4.72 MB（排除 `artifacts/`、构建产物、商业 SDK 二进制与签名私钥；仓库根含
  `LICENSE`）。解包复算源码摘要与版本封印值 `0FAAB232…` 逐位一致（见第 6 节）；
  压缩包自身的 SHA-256 见随包 `NovaProtect-2.3.2-source.zip.sha256`。

## 6. 版本封印

- `tools/version.ps1 -Action Seal` 写入 `version-lock.json`：客户端 `2.3.2`，
  源码摘要 `0FAAB2322743104FA54E9CC738ACB916CEC5A4D9E11368B4DFA5FB4C57D798CA`；
  解包 GitHub 源码包复算摘要与封印值逐位一致（166 个受摘要覆盖的源文件）。
- 封印前发现并修复 `Get-SourceDigest` 的缺陷：构建产出目录排除原按**完整路径**
  匹配 `\artifacts\` 等段，而本工作区自身位于 `artifacts/github-source/` 下，导致
  `src/`、`include/`、`tools/`、`website/` 等全部被误排除——封印摘要实际只覆盖
  8 个根文件，源码改动不会被检测到。改为按**相对路径**匹配后覆盖 166 个文件；
  `tools/package-github-source.ps1` 遍历本就用相对路径，不受影响。
