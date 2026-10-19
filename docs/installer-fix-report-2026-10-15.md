# NovaProtect 2.1.4 安装入口修复报告

- 日期：2026-10-15（Asia/Shanghai）
- 网站版本：2.1.4
- 客户端版本：2.0.7（未修改）
- 安装包：`artifacts/NovaProtect-Website-2.1.4-Linux-x64-BaoTa.zip`
- 文件大小：92,433,247 字节
- SHA-256：`20A5BF33562AC50AFD364471D72DF2ED9B6D98467DD751F31F7569FF5929321A`

## 根因与修复

ZIP 根目录的 `install.sh` 会转交给 `deploy/install.sh`。旧逻辑把被调用脚本所在的 `deploy/` 目录当作包根目录，于是尝试读取不存在的 `deploy/VERSION`。新逻辑从 `deploy/install.sh` 的父目录解析包根，并在任何服务器变更前校验必需文件及 `SHA256SUMS`。新增只读检查命令：

```bash
bash install.sh --check-package
```

修复同时覆盖从 ZIP 根目录、`deploy/` 目录以及其他当前工作目录调用入口的场景。

## 本地验证

- 9 项 BaoTa/Nginx 配置测试通过。
- 8 项安装入口测试通过，包含缺失 `VERSION`、篡改负载哈希、Bash 语法及根入口/部署入口路径。
- 对最终 ZIP 独立执行包验证：18 个文件全部匹配 `SHA256SUMS`，客户端 EXE 哈希匹配 `release.json`，实际解压后的 Bash 入口回归测试通过。
- 打包成功后自动删除本次生成的展开 staging 目录；保留客户端安装包、VMP 产物和签名材料。

## 尚待服务器验收

Windows 工作区没有 PHP CLI、Linux PHP-FPM、宝塔或 CDNfly 控制台，因此尚未声称生产 PHP 运行时或客户端联网流程已验收。服务器上传此 ZIP 后，在解压根目录依次执行：

```bash
bash install.sh --check-package
bash install.sh
```

安装完成后打开 `/install` 完成浏览器安装向导，再按既有生产验收清单检查 `/health`、账户登录、客户端连接和 CDNfly 旁路缓存规则。
