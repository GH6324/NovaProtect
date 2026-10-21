# NovaProtect 2.2.7

NovaProtect 是 Windows EXE 保护工作台，正式入口为 **NovaProtect.exe**，官网为 `https://nova.fbi.plus`。

## 客户端能力

- 支持 C/C++、C#/VB .NET、Rust、Golang EXE 的识别和规划；实际处理按 PE/CLR 格式，不按语言标签伪装能力。
- 函数/区域对象编辑器只接受目标文件中的真实 NovaProtect SDK marker；不把任意符号、导出、反编译结果或 VMProtect SDK 导入伪装成可选函数。
- 项目配置、导入/导出和构建前快照持久化请求值、生效值、跳过项、冲突项、marker 来源和架构能力矩阵。
- x86、x64、ARM64、原生 PE 和 .NET 的边界在规划前明确展示；ARM64 当前只读识别，.NET 为安全封装而非 IL 虚拟化。
- 资源区段加密时保留 `RT_ICON`/`RT_GROUP_ICON`：加密后文件在资源管理器中显示的图标与原文件逐字节一致。

## 官网与安装包

网站已经重构为 PHP 8.4，适配 Linux 宝塔 Nginx + PHP-FPM，带浏览器安装向导、客户端下载、更新日志和管理后台（客户端发布上传、离线升级）。每次发布同时生成完整安装包和精简升级包：

```text
artifacts/website-full/2.2.14/NovaProtect-Website-2.2.14-Linux-x64-BaoTa-Full.zip
artifacts/website-upgrade/2.2.14/NovaProtect-Website-2.2.14-Linux-x64-BaoTa-Upgrade.zip
```

完整包从 ZIP 根目录解压后运行 `bash install.sh`，用于首次安装或完整恢复；已有网站只使用升级包，运行 `bash upgrade.sh --check-package` 后再运行 `bash upgrade.sh`。升级包不含完整安装入口和初始 Nginx 配置。两种包都会先校验 ZIP 布局、SHA-256 和客户端安装包，升级还会备份、迁移数据、执行健康检查并支持 `bash deploy/rollback.sh` 回滚。不会创建新的 ASP.NET systemd 应用服务。

网站只有一个管理员口令。忘记口令时不需要重装：用 root 在 SSH 执行 `php /www/server/novaprotect/bin/reset-admin-password.php`（安装/升级时自动部署，仅 root 可读写），按提示输入两次新口令即可，旧会话全部失效。工具会自动定位站点 app 目录（`/www/wwwroot/nova.fbi.plus/current/app`），也可先用 `--locate` 诊断位置，详见 `website/deploy/README.md`。

## 正式客户端

```text
artifacts/client-installer/2.2.7/NovaProtect-Setup-2.2.7.exe
SHA-256: 61A219532A81839191ABCA100CB405A5323CA16790BAB2B84C259E806FF687A3
```

网站版本与客户端版本独立记录：网站版本为 `2.2.14`，客户端安装包版本为 `2.2.7`。

## 构建与验证

```powershell
pwsh -NoProfile -File .\tools\version.ps1 -Action Check
python -m unittest tests/deploy_config_test.py -v
python tests/client_release_upload_smoke.py
pwsh -NoProfile -File .\tools\package-website.ps1
pwsh -NoProfile -File .\tools\verify-website-package.ps1
python -B -m unittest tests/website_installer_test.py -v
```

本地使用 PHP 8.4 CLI 完成健康检查、安装向导、客户端 EXE 上传与下载回归；宝塔 Linux 实机仍需按部署 README 验收 PHP-FPM socket、Nginx reload 和 CDNfly。

## 客户端打包（无 VMProtect 后处理）

```powershell
# 完整流程：版本检查 -> 全量构建 -> Inno Setup 安装包 -> release.json -> 本地 E2E
pwsh -NoProfile -File .\tools\package-client-release.ps1

# 复用已有构建产物、跳过本地站点 E2E
pwsh -NoProfile -File .\tools\package-client-release.ps1 -SkipBuild -SkipE2E

# 打包前先跑回归套件
pwsh -NoProfile -File .\tools\package-client-release.ps1 -RunTests
```

产物为 `artifacts\client-installer\<版本>\NovaProtect-Setup-<版本>.exe`（附 `.sha256`），脚本同步更新 `website/release.json` 的 `fileName` 与 `sha256`，并通过本地 PHP 测试站点跑一遍匿名检查更新、下载与 SHA-256 校验。源码里的 VMProtect SDK marker 调用保留：装了商业 SDK 就链接真实导入库，未安装则编译为 no-op（`NOVAPROTECT_VMP_STUB`），开源克隆无需任何 VMProtect 组件即可构建。

## GitHub 源码包

```powershell
pwsh -NoProfile -File .\tools\package-github-source.ps1
```

生成 `artifacts\github-source\NovaProtect-<版本>-source.zip`（含顶层 `NovaProtect-<版本>/` 目录），排除 `artifacts/`（签名私钥、VMP 产物）、`output/`、构建中间物、商业 SDK 二进制与调试临时文件；`.gitignore` 已覆盖同类路径。仓库根已包含 `LICENSE`。

## 清理原则

保留源码、SDK、正式客户端、签名材料、文档和证据；删除旧 ASP.NET 网站源码、缓存、临时日志、测试输出和重复构建物。`tools/clean-workspace.ps1 -Apply` 只删除脚本明确列出的可重建项。上传 GitHub 的源码包由 `tools/package-github-source.ps1` 生成，排除 `artifacts/`（含 VMP 产物与签名私钥）、`output/` 等本地构建产物。
