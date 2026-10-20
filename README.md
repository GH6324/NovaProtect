永久免费,尽力维护,远程更新端与客户端全部开源,请勿加验证,加壳倒卖,公益不易,且行且珍惜

后续会仿制正版的VMP和themida,同步更新最新版(DMCA警告哈哈哈哈),让资金紧缺的开发者,也能享受到最好的保护

本软件承诺,不逆向正版的VMP和themida,只摸索思路

NovaProtect 是 Windows EXE 保护工作台，官网为 https://nova.fbi.plus

客户端能力
- 支持 C/C++、C#/VB .NET、Rust、Golang EXE 的识别和规划；实际处理按 PE/CLR 格式，不按语言标签伪装能力。
- 函数/区域对象编辑器只接受目标文件中的真实 NovaProtect SDK marker；不把任意符号、导出、反编译结果或 VMProtect SDK 导入伪装成可选函数。
- 项目配置、导入/导出和构建前快照持久化请求值、生效值、跳过项、冲突项、marker 来源和架构能力矩阵。
- x86、x64、ARM64、原生 PE 和 .NET 的边界在规划前明确展示；ARM64 当前只读识别，.NET 为安全封装而非 IL 虚拟化。
- 资源区段加密时保留 RT_ICON/RT_GROUP_ICON：加密后文件在资源管理器中显示的图标与原文件逐字节一致。
官网与安装包
网站已经重构为 PHP 8.4，适配 Linux 宝塔 Nginx + PHP-FPM，带浏览器安装向导、客户端下载、更新日志和管理后台（客户端发布上传、离线升级）。每次发布同时生成完整安装包和精简升级包：
artifacts/website-full/2.2.14/NovaProtect-Website-2.2.14-Linux-x64-BaoTa-Full.zip
artifacts/website-upgrade/2.2.14/NovaProtect-Website-2.2.14-Linux-x64-BaoTa-Upgrade.zip
完整包从 ZIP 根目录解压后运行 bash install.sh，用于首次安装或完整恢复；已有网站只使用升级包，运行 bash upgrade.sh --check-package 后再运行 bash upgrade.sh。升级包不含完整安装入口和初始 Nginx 配置。两种包都会先校验 ZIP 布局、SHA-256 和客户端安装包，升级还会备份、迁移数据、执行健康检查并支持 bash deploy/rollback.sh 回滚。不会创建新的 ASP.NET systemd 应用服务。
网站只有一个管理员口令。忘记口令时不需要重装：用 root 在 SSH 执行 php /www/server/novaprotect/bin/reset-admin-password.php（安装/升级时自动部署，仅 root 可读写），按提示输入两次新口令即可，旧会话全部失效。工具会自动定位站点 app 目录（/www/wwwroot/nova.fbi.plus/current/app），也可先用 --locate 诊断位置，详见 website/deploy/README.md。
正式客户端
artifacts/client-installer/2.2.7/NovaProtect-Setup-2.2.7.exe
SHA-256: 61A219532A81839191ABCA100CB405A5323CA16790BAB2B84C259E806FF687A3
网站版本与客户端版本独立记录：网站版本为 2.2.14，客户端安装包版本为 2.2.7。
构建与验证
pwsh -NoProfile -File .\tools\version.ps1 -Action Check
python -m unittest tests/deploy_config_test.py -v
python tests/client_release_upload_smoke.py
pwsh -NoProfile -File .\tools\package-website.ps1
pwsh -NoProfile -File .\tools\verify-website-package.ps1
python -B -m unittest tests/website_installer_test.py -v
本地使用 PHP 8.4 CLI 完成健康检查、安装向导、客户端 EXE 上传与下载回归；宝塔 Linux 实机仍需按部署 README 验收 PHP-FPM socket、Nginx reload 和 CDNfly。
客户端打包（无 VMProtect 后处理）
# 完整流程：版本检查 -> 全量构建 -> Inno Setup 安装包 -> release.json -> 本地 E2E
pwsh -NoProfile -File .\tools\package-client-release.ps1

# 复用已有构建产物、跳过本地站点 E2E
pwsh -NoProfile -File .\tools\package-client-release.ps1 -SkipBuild -SkipE2E

# 打包前先跑回归套件
pwsh -NoProfile -File .\tools\package-client-release.ps1 -RunTests
产物为 artifacts\client-installer\<版本>\NovaProtect-Setup-<版本>.exe（附 .sha256），脚本同步更新 website/release.json 的 fileName 与 sha256，并通过本地 PHP 测试站点跑一遍匿名检查更新、下载与 SHA-256 校验。源码里的 VMProtect SDK marker 调用保留：装了商业 SDK 就链接真实导入库，未安装则编译为 no-op（NOVAPROTECT_VMP_STUB），开源克隆无需任何 VMProtect 组件即可构建。

NovaProtect 将目标分析、保护配置、关键区域管理和构建输出整合到统一工作台，帮助开发者为核心算法与业务逻辑配置保护措施。开发者可以根据目标程序的架构、兼容性和运行开销，选择适合项目的保护组合。

产品可处理 C/C++、Rust、Go 等工具链生成的受支持原生 EXE，并为 C#、VB .NET EXE 提供加密封装。实际能力由文件格式、处理器架构和可处理的代码区域共同决定。

**产品价值**

关键逻辑按需保护。通过 NovaProtect SDK 指定重点区域，在受支持的原生 x64 程序中应用局部虚拟化及 VM 前置变异，增加理解关键代码所需的分析工作。

配置效果清晰可见。构建前展示请求项、生效项、跳过项与冲突原因；项目文件和历史快照保留配置与处理结果，便于持续维护和问题定位。

**软件构成**

| 组成部分      | 主要作用                                 |
| --------- | ------------------------------------ |
| 可视化客户端    | C# 与 WinUI 3 界面，提供项目配置、区域编辑、构建进度和日志。 |
| 原生保护引擎    | C++ 实现 PE 分析、区段处理、虚拟指令转换与输出构建。       |
| 保护运行时     | 包含 x86/x64 加载器、x64 解释器与 .NET 专用启动宿主。 |
| SDK 与项目管理 | 标记关键区域，保存区域规则、项目配置和构建快照。             |
| 官网与用户服务   | 提供客户端下载、版本说明与问题反馈。              |

**加密与保护原理**

NovaProtect 采用分层处理流程。引擎先识别目标程序的结构与能力，再对符合条件的区段、SDK 区域及导入信息应用相应措施，最后生成保护输出与构建记录。

**原生区段保护**

针对符合条件的代码区段以及可选资源区段进行打包；在压缩能够缩小载荷时使用压缩，并在启用区段加密时采用 XOR 编码。程序启动后，由对应架构的加载器恢复载荷。该路径用于改变程序在磁盘上的直接表示形式。

**关键区域虚拟化与代码变异**

针对原生 x64 程序中由 NovaProtect SDK 标记、能够成功翻译的代码区域，将机器指令转换为内部虚拟指令，运行时交由解释器执行。虚拟指令采用映射表编码，Ultra 管线还可在转换前执行代码变异，并对适用字节码追加混淆。

这使关键区域的分析需要进一步理解内部指令与执行流程。具体区域能否处理，以指令支持情况、区域空间和构建结果为准。

**VM 字节码组合加密**

生成的 VM 字节码采用 RC4、XOR 与字节加法组合处理，并结合区域随机参数及区域位置派生处理参数。运行时按对应顺序恢复字节码，再交给解释器执行。

**导入保护与运行时校验**

原生 x86/x64 导入保护保存导入信息，并由加载器在运行时重建导入地址表。根据目标与配置，还可执行载荷或代码区域完整性校验；原生 x64 进一步提供许可数据校验和启动前机器标识绑定。

**托管程序加密封装**

对受支持的 C#、VB .NET EXE，使用基于 XTEA 的载荷加密，由专用宿主完成解密、完整性校验与程序启动。当前方案保留原始 CLR 元数据和 IL 结构，采用封装方式接入原有运行环境。

**设计理念与适用范围**

NovaProtect 的设计着重于让开发者理解保护对象、配置作用和构建结果，使代码保护能够融入项目维护与版本发布流程。

**保护对象明确**

区域对象来自目标文件中的真实 NovaProtect SDK 标记。开发者可以结合代码价值、性能要求和兼容性，确定需要处理的关键区域，并为区域设置相应规则。

**配置与结果可核查**

兼容、均衡、高强度和 Ultra 等预设提供配置起点。构建计划进一步说明哪些请求实际生效、哪些被跳过以及是否存在冲突；历史快照记录项目配置与构建结果，便于后续复用和核查。

**产品设计参考**

NovaProtect 的产品设计主要参考 VMProtect Professional 与 Themida。VMProtect Professional 提供了项目与代码区域组织、属性配置、保护模式和构建日志方面的参考；Themida 提供了 SDK 宏标记关键区域、按模块组织保护能力方面的参考。

这些参考体现在产品组织与操作流程中，不代表复现相关产品的全部功能、内部算法或保护强度。NovaProtect 围绕自身的 SDK、保护引擎和构建计划提供对应功能。

**当前能力概览**

| 目标类型             | 区段或载荷保护 | SDK 区域 VM | 许可与机器绑定 |
| ---------------- | ------- | --------- | ------- |
| 原生 x86 EXE       | 区段打包与编码 | 暂不支持      | 暂不支持    |
| 原生 x64 EXE       | 区段打包与编码 | 支持适用区域    | 支持      |
| C# 与 VB .NET EXE | 加密封装    | 暂不支持      | 暂不支持    |
| ARM64            | 只读识别    | 暂不支持      | 暂不支持    |

原生导入保护覆盖受支持的 x86/x64 目标；.NET 当前提供加密封装，尚未实现 IL 虚拟化；ARM64 暂不生成保护输出。实际可用项目以客户端构建计划和目标程序验证结果为准。
