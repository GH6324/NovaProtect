# Field journal — NovaProtect 2.0.7 — 2026-10-15

## Observed：执行链

1. 复用已有全文件 VMP 盘点/候选，未重复 495 个 PE 构建。
2. 补编 UI ModuleInitializer，重新保护单个 NovaProtect.dll；旧原件/候选保留在 vmp-work-2.0.7/pre-module-initializer。
3. 个别第三方库 VMP 工具接受且单文件 UI 启动成功，但组合后 prebuild JSON 文件为 0 字节，保护未开始。
4. 同 runtime 版本的独立 planner（直接编译实际 ProjectStore 源码）分组/单文件对照定位 System.Console、System.IO.Pipelines、System.Memory；它不是发行调用后门。
5. 调整后的 UI 五语言成功，但账户合同和外部宿主拒绝路径仍失败；native-only 组合的账户成功不代表 FailFast 成功。
6. 回到干净边界：自有四组件 VMP＋原始第三方依赖。最终真实 UI 五语言、七个拒绝用例与正向反例均通过，不发布失败组合。
7. 宝塔配置器 8 项测试与 Bash 语法检查通过；本地浏览器完成注册、账户、退出和窄屏验证。Linux ELF 本机不执行。

## 踩坑与修正

- Windows 退出与句柄释放异步：等待退出、清理重试，保存/恢复已验证项。
- 硬链接试验必须先 unlink 再写；破坏试验只改独立副本。
- PSCustomObject 新属性必须 Add-Member；直接赋不存在的 Reason 失败后修正，不重做 VMP 构建。
- UTF-8 无 BOM 中文脚本使用 PowerShell 7；Windows PowerShell 5.1 会误读。
- UI 自动化需等待预设弹窗关闭/控件重新出现；UI 测试串行，避免负面启动同时干扰窗口事件。
- FailFast 测试设置 SEM_NOGPFAULTERRORBOX，避免错误对话框阻塞；超时不算通过。
- 不发布 VMProtect 原始注册日志；公开记录仅 mask、对象数、状态和哈希。
- JSON、反射、异常及 FailFast 对 CLR runtime 有独立要求，单一启动探针不足以确认运行库可发行。

## 可复用经验

- 保护器发行验收四种合同：启动、业务、账户、拒绝/损坏路径。
- 自有源码的真实 SDK marker 可审计；UI object count=0 时不可宣传任意函数 Ultra。
- 官网 ZIP 同时带自包含程序、源码、固定域名安装器和自动 Nginx 配置，版本与下载哈希闭环。
- 交叉编译/配置单测不能替代源站 Linux 部署和 CDNfly 边缘验收。

经验索引：docs/experience-index.md。密钥、注册身份、测试账户不进入交付物。
