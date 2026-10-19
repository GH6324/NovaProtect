# NovaProtect 竞品分析与落地记录

更新日期：2026-10-14

## 范围与证据边界

本记录只用于合法的软件保护产品设计、配置建模和 UI 信息架构。没有实现破解、授权绕过、规避安全工具、虚拟机拒绝执行或隐蔽逃逸能力。

结论分为三类：

- **观察**：由本地随附工件或 REA 证据直接支持。
- **推断**：由多个观察归纳出的产品设计判断，不等于运行时事实。
- **未知**：当前证据没有建立的行为、强度、兼容性或实现细节。

本轮使用的 REA 证据：

| 目标 | 证据 | 用途 |
| --- | --- | --- |
| Themida.exe | `ev_49ee071dbeb17b256c28678cd6544e32f27fae716d0cd5e0ede8dd8fe7f15aa7` | PE 资源树与静态工件身份 |
| Themida64.exe | `ev_627fdf91fdbb6f19ed4613ee03b444e0493d04e191ac94181752103e4856356c` | 64 位 PE 资源树与静态工件身份 |
| VMProtect.exe | `ev_3bd1292913fbe29124ef3f7ccce86e46a857250308a211a2db2f66bd0024b077` | Ghidra 原生 overview |
| VMProtect.exe | `ev_c8ec018ba9d697984425ba2eaf0702940d280d54eb8610ccadd476fa48d096fa` | PE 资源树与图标资源 |

此前已取得的同一调查会话证据还包括 Themida 的资源/字符串记录和 VMProtect 的 SDK、中文语言文件观察；这些记录用于产品分类归纳，不作为运行时行为证明。

## Themida：可借鉴的强项

### 观察

随附 SDK 明确暴露了 VM、Mutation、字符串加密、未保护区域、代码替换、注册/未注册代码路径、注册绑定 VM 和完整性/注册状态检查等区域标记与接口。Themida 的 GUI 配置文件还呈现了 `virtual_machine`、`protection_macros` 和 `xbundler` 视图，其中虚拟文件视图带有 Virtual Files、Mode、Original File Location 等列。PE 资源证据表明主程序和 64 位程序都有完整资源树与图标资源。

### 产品设计推断

Themida 最值得借鉴的不是单一“强度”数字，而是把保护对象建模为项目、区域标记、VM 实例和虚拟文件的组合。对应到 NovaProtect，应优先提供：

1. 保护区域/函数对象列表，而不是只提供全局滑块。
2. 虚拟文件表格，列出路径、模式、原始位置和是否嵌入。
3. 每个区域显示兼容性、体积和性能影响。
4. SDK 标记与项目配置之间的明确映射。

### 未知

当前证据没有建立 Themida 各强度值的内部算法、运行时依赖、兼容性边界或保护效果排名。NovaProtect 不应把这些未知内容写成“同等实现”。

## VMProtect Professional：可借鉴的强项

### 观察

VMProtect 的中文语言文件与 SDK 直接显示出较清晰的产品分类：常规保护、Mutation、Virtualization、Ultra、Complexity、VM instances、VM version、函数级保护，以及 Debugger、虚拟化工具、内存/导入/资源保护、Packing、Strip debug info、Strip relocations、Watermarks、Licensing parameters、HWID、过期时间、运行时间/次数、最大构建日期、客户数据、在线/离线激活、Templates、Projects、Compilation Log 等。

SDK 还提供 Virtualization、Mutation、Ultra 和按 key 锁定的区域标记，以及调试器、VM、image CRC 检查、字符串解密 API 和 serial 状态/激活流程 API。

### 产品设计推断

VMProtect 最值得借鉴的是“项目/文件/函数对象 + 右侧属性面板 + 构建日志”的信息架构，以及把许可参数和保护参数分开。对应到 NovaProtect，本轮已落地：

- 保护模式与预设：兼容、均衡、高强度、Ultra。
- 保护能力分组：代码处理、运行时、输出处理、许可/标识/虚拟文件。
- 构建前显示 requested/effective/skipped 摘要。
- x64 与非 x64 的能力边界提示。
- 保留检查工具、运行记录和实时日志。

### 未知与安全边界

静态 SDK 和语言文件不能证明所有功能在当前版本的具体运行时实现。NovaProtect 不复制反调试规避、虚拟机拒绝执行、API 隐藏或安全工具规避等高风险设计；现有反调试/环境检查能力也不在默认预设中强化。

## NovaProtect 当前落地状态

### 已实现并保留

- x64 代码变异、VM、Ultra 模式及复杂度/强度参数。
- 内存完整性、导入保护、资源保护、压缩、调试目录处理。
- 水印、许可密钥、虚拟文件、PE 信息/水印/虚拟文件检查。
- WinUI 3 / C# 客户端、Mica、圆角 Fluent 表面、深浅色主题、拖放、实时日志和取消。
- 兼容、均衡、高强度、Ultra 预设。

### 本轮新增并验证

- **区段加密**：UI 可显式启停；`-noencrypt` 会清除 payload 区域的加密 flag，x86/x64 loader 均只在 flag 存在时解密。
- **重定位裁剪**：原生 EXE 可清空 Base Relocation 目录并关闭 ASLR；DLL 在 UI 规划器和 CLI 中均被阻止。
- **导出裁剪**：原生 EXE 可清空 Export 目录；DLL 在 UI 规划器和 CLI 中均被阻止。
- **导入虚拟化**：x86/x64 均通过剥离 loader 可见目录并在运行时重建 IAT 完成，已纳入回归。
- **激活绑定**：原生 x64 已具备运行时机器 ID 校验闭环；`-machineid` 输出当前机器 ID，`-activation auto` 绑定构建机，也可传入 1–16 位十六进制 ID。错误机器 ID 会在进入原始入口点前被拒绝。x86、ARM64 与 .NET 目标不开放此能力。
- **对象编辑器**：对象只来自 NovaProtect SDK BEGIN/END marker 的真实字节边界；VMProtect SDK 调用、导出、符号和反编译结果不会被伪装成对象。
- **项目与构建计划**：项目 JSON 可保存/导入；requested/effective/skipped/conflicts 在构建前和构建后持久化到输出旁与本地历史目录。
- **架构矩阵**：已区分 x86、x64、ARM64、原生 EXE、原生 DLL 与 .NET；无 loader 或无 CLR-aware 重建路径的目标直接拒绝。

### 仍需后续建设

- 激活绑定当前是进程级前置校验；对象编辑器中的“要求启用全局激活绑定”只表达该 marker 规则对全局绑定的依赖，不宣称存在独立的区域级授权状态。
- ARM64 loader 与 .NET CLR-aware 重建/虚拟化仍未实现，能力矩阵和 CLI 会保持 fail-fast。

## 设计结论

NovaProtect 应继续采用“左侧项目与分类、中间对象列表、右侧属性、顶部构建动作、底部日志”的方向，但当前客户端先以可信配置为优先：任何开关都必须对应可验证的核心行为；不支持的项显示原因并在 CLI 层拒绝。该原则比增加更多看似完整的开关更重要，也为后续函数级保护和项目模板提供了稳定边界。
