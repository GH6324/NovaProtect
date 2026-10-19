# Field journal — 2026-10-14

## 执行链路

1. 复用既有 REA 证据和二进制身份，不重复打开相同目标。
2. 编译 core，确认 stub、protection runtime 和 CLI 成功。
3. 首次 WinUI 编译发现 `SelectTag` 缺失，补充按 `ComboBoxItem.Tag` 选择并提供安全默认值。
4. 扩展回归：区段加密 flag、重定位/导出目录、DLL 冲突、激活 metadata、错误机器 ID、marker 选中/跳过/伪范围。
5. 新增 planner smoke，直接复用 UI model/service 源文件验证项目 round-trip、构建计划 JSON 和架构矩阵。
6. 修复 planner 对 .NET 的错误冲突顺序、DLL 裁剪被同时列为 effective 的问题、marker 实际选中数量统计。
7. 完成全量构建和回归，启动最终 WinUI 实例。
8. 将目标专用能力列表扩展为横向完整矩阵，并修正 x86 loader 实际已支持 region 内存完整性、但规划器曾错误标记为仅 x64 的不一致。
9. 为 marker 规则增加来源和检测器版本校验；为构建计划增加 PlanId、stage、独立 prebuild 快照和毫秒级唯一历史文件。

## 踩坑

- PowerShell 回归函数把参数命名为 `$Args`。这是自动变量，调用时传入的选项被静默丢弃，导致新增用例表面通过但实际未传 CLI 参数。改名为 `$Options` 后，metadata/flag 断言才真正覆盖目标路径。
- 仅验证进程退出码不足以证明裁剪或加密选项生效；必须同时解析 PE Data Directory、DLL Characteristics、NOVA payload flags 和 NPP1 descriptor。
- `VMProtectSDK.h` 的 begin/end API 不等于 NovaProtect SDK marker。对象编辑器和核心都必须只认 NovaProtect marker 字节边界。
- Computer Use native pipe 本轮不可用，因此窗口验证退回到进程、窗口标题和响应状态；没有重复尝试 UI 自动化。

## 可复用模式

- 对保护器选项采用“双验证”：运行结果 + 静态结构断言。
- UI 规划器输出必须区分 requested、effective、skipped、conflicts；被阻止的能力不得同时出现在 effective。
- marker 编辑器必须保存 RVA 边界并在构建时重新匹配当前文件，避免项目文件把旧对象规则应用到不同二进制。
- 架构不支持时 fail-fast 优于生成“看似成功”的不可靠文件。

## 后续建议

- 若实现对象级激活，扩展 32 字节 VM descriptor 的保留字段并给每个 descriptor 定义明确授权 flag；runtime 安装 trampoline 前逐 descriptor 校验。
- ARM64 与 .NET 应建立独立 loader/rebuild 路径，不复用 x64 假兼容逻辑。
- 将 planner smoke 纳入 `tests/regress.ps1` 已完成；后续 CI 应同时保留 CLI 结构断言与 WinUI 编译。

