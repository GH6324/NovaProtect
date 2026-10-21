# NovaProtect 项目状态

- **网站版本**：2.2.17
- **正式客户端版本**：2.3.2
- **主程序**：NovaProtect.exe
- **官网**：https://nova.fbi.plus
- **部署栈**：PHP 8.4 / PHP-FPM / Linux 宝塔 Nginx / CDNfly

## 已完成

1. 官网从 ASP.NET Core 迁移到 PHP，保留下载、更新日志、健康检查和浏览器安装向导。
2. `2.2.12` 移除账号/会员系统：没有用户注册、登录、邮箱验证、问题反馈或极验验证码；网站只保留匿名客户端下载、更新日志和一个管理员口令保护的后台（客户端发布上传、离线升级）。
3. 安装包支持 `bash install.sh` 一键部署、PHP-FPM socket 探测、Nginx 配置备份、发布槽位切换、SHA-256 校验和失败回滚。
4. 所有页面、API、下载和静态资源使用不缓存响应头；客户端固定 HTTPS 官网地址，匿名检查更新与下载，无需会话。
5. 客户端和网站版本独立管理；网站版本为 2.2.17，客户端安装包版本为 2.3.2。
6. 对象编辑器、项目快照和架构能力矩阵继续以真实 NovaProtect SDK marker 和实际格式能力为准。
7. 管理后台支持离线升级 ZIP 上传、版本递增和 SHA-256/路径/入口校验；包暂存于 `/www/server/novaprotect/updates`，由 root 执行器自动复核、备份、迁移、健康检查并回滚。
8. 管理员口令在安装向导一次性设置，Argon2id（不可用时 PBKDF2-SHA256 60 万次）哈希保存；`/admin/login` 提供登录页，未登录访问 `/admin` 跳转登录页，登录有速率限制。
9. `2.2.13` 新增 SSH 管理员口令重置：`php /www/server/novaprotect/bin/reset-admin-password.php`（安装/升级自动部署，仅 root），支持交互、`--password`、`--stdin`、`--generate`；重置后旧口令立即失效、全部后台会话失效并清除登录限速，功能测试固化于 `tests/website_installer_test.py`。
10. `2.2.14` 修复 SSH 口令重置工具在已安装站点找不到 app 目录的问题：install.sh/upgrade.sh 把站点根写入 `/www/server/novaprotect/site-root`，工具按 `--app` → `NOVAPROTECT_APP_DIR` → 包内 app → site-root/current → state/current → `/www/wwwroot/nova.fbi.plus/current` → `/www/wwwroot/*/current|app` 顺序探测，新增 `--locate` 诊断模式，失败时给出排查命令；站点在 `/www/wwwroot/<域名>/current/app`，与 state 目录是两棵不同的树。
11. `2.2.12` 修复后台路由契约：登出后 `/admin` 302 跳转 `/admin/login`，`GET /admin/login` 返回登录页，`/client-updates` 更新日志页补上路由。
12. 资源区段加密时保留 `RT_ICON`/`RT_GROUP_ICON`：加密后文件在资源管理器中的图标与原文件逐字节一致（回归用例固化于 `tests/regress.ps1`）。
13. 客户端发布打包不再经过 VMProtect 后处理，直接正常打包；源码保留 VMProtect SDK marker 底子。上传 GitHub 的源码包由 `tools/package-github-source.ps1` 生成，排除构建产物与签名私钥。
14. `tools/package-client-release.ps1` 一键完成版本检查、全量构建、Inno Setup 安装包、`website/release.json` 元数据同步与本地 PHP 站点 E2E（匿名检查更新、下载、SHA-256 校验）；`tools/package-github-source.ps1` 生成 `NovaProtect-<版本>-source.zip`。
15. `2.3.1` 修复反沙箱拦截路径崩溃（prot64 blob 数据表绝对指针改定宽字符矩阵，build.ps1 增加构建期扫描断言）；全量重建后打包 `NovaProtect-Setup-2.3.1.exe`（58.1 MB，SHA-256 `6a4c457f…282e`），PHP E2E 72 项全过；官网同步升级 `2.2.16`，产出 Full/Upgrade 两个部署 ZIP。
17. `2.3.2` 新增手动函数保护（VMP 式函数扫描）：客户端「保护」页对 x64 目标读 `.pdata` 枚举全部运行时函数，支持勾选 / 全选 / 批量模式一键「添加所有函数」；引擎侧新增 `-func` 区域规格（FunctionSource=ScanFunction），函数级虚拟化只虚拟化到第一个 RET 之前、尾跳落在 RET 上由原生指令返回；区域表上限 64（与 runtime `np_vm_install` 一致）。同轮修复三个引擎级缺陷：REX.W 立即数符号扩展（变异 `add imm→sub -imm` 引入负立即数时 VM 算错）、x64 流 32 位操作数门禁（wire VM 为 64 位机，无法复现高 32 位清零与 32 位标志）、trampoline 调用者保存寄存器保留集（`rax/rcx/rdx/r8-r11` 会被解释器参数与 C ABI 破坏，编译器跨调用在这些寄存器里放活值即被踩）。E2E：变异强度 0-3 × 复杂度 6 全对；186 函数全保护（64 虚拟化 + 其余如实跳过）程序输出不变；回归 40 OK / 5 SKIP / 1 FAIL（缺 x86 fixture 的既定基线）。
16. 修复 PowerShell 5.1 无 BOM `.ps1` 按 GBK 读取导致 `installer/version.iss` 中文发布说明双重编码的问题（version.ps1 加 UTF-8 BOM）；安装包 PE 版本资源中文已验证正确，官网更新日志数据源无乱码。更新冒烟测试的强制更新 fixture 改为按当前版本动态生成，不再随版本升级过期。

## 生产验收

- [x] ZIP 中不包含 ASP.NET 项目、私有数据、密钥和旧 website service。
- [x] ZIP 安装脚本不创建新的 ASP.NET systemd 服务。
- [x] ZIP 根目录与 `deploy/` 安装入口均按包结构定位 `VERSION`，支持只读包校验。
- [x] Nginx 配置保留站点 listen/TLS/日志，并切换到 PHP-FPM。
- [x] 清理旧试验二进制、历史快照、调试文件和测试缓存；正式产物与签名材料保留。
- [ ] 上传 `artifacts/website-upgrade/2.2.14/` 下的升级 ZIP 后，在宝塔 Linux 实机执行 `bash upgrade.sh` 完成升级；新站点的 `/install` 应保持锁定。
- [ ] CDNfly 应用最高优先级动态规则并清理旧缓存后，运行 `bash deploy/cdnfly-check.sh https://nova.fbi.plus` 验收下载、`/api/*` 和 `Cache-Control: no-store`。

## 未决项

当前 Windows 工作区没有 Linux PHP-FPM 和 CDNfly 控制面，无法在本地替代宝塔实机验收；本轮已用本地 PHP CLI / 内置 HTTP 服务器完成客户端 EXE multipart 上传回归。上传 ZIP 后若失败，优先查看 `journalctl -u nginx`、宝塔 PHP-FPM 日志以及安装脚本生成的 `/www/server/novaprotect/backups/*`。
