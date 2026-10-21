# NovaProtect SDK

给应用代码打标记，让 NovaProtect 客户端在打包时把这些函数/区域虚拟化或混淆。

## 目录

- `include/novaprotect_sdk.h` — C/C++ 头文件，提供 `NOVAPROTECT_BEGIN(name)` / `NOVAPROTECT_END()`。
- `examples/example.cpp` — C++ 使用示例（普通函数体打标记）。
- `examples/example_vm.S` — 寄存器直通、可真正虚拟化的手写汇编示例。
- `examples/example_driver.c` — 汇编示例的驱动，验证结果一致。

## 用法

```cpp
#include "novaprotect_sdk.h"

int secret(int x)
{
    NOVAPROTECT_BEGIN("secret");
    // 函数体
    NOVAPROTECT_END();
    return ...;
}
```

编译后，把 EXE 拖进 NovaProtect 客户端，选择「虚拟化」或「Ultra」模式即可。

## 手动添加函数保护（VMP 式函数扫描）

除 SDK 标记外，客户端「保护」页提供函数扫描器：对 x64 目标读取 `.pdata`
异常目录枚举全部运行时函数（含静态函数），勾选后即可对整个函数体做 VM
保护，无需改源码、打标记。

- 扫描结果按 RVA 排序，显示名称 / 地址 / 所在节 / 大小 / 是否导出 / 是否含栈帧。
- 「添加所有函数」一键全选；批量设置模式（继承 / 虚拟化 / Ultra / 变异 / 跳过）、
  VM 复杂度、变异强度与激活锁定。
- 区域表上限 64：超过时打包器按 RVA 顺序取前 64 个，其余保持原生并如实提示。
- 函数级虚拟化只虚拟化到**第一个 RET 之前**：wire VM 没有返回指令，运行时
  trampoline 尾跳正好落在该 RET 上，由原生指令完成返回，调用约定不变。

## 重要约束

VM 解释器只处理纯寄存器、直线型 x86-64 子集。以下形式会被安全地跳过
（保留为原生代码，功能不受影响）：

- 访问 `RSP`/`RBP` 或内存（`[reg+disp]`、RIP 相对寻址）；
- 32 位操作数形式（非 `REX.W` 的 `mov/add/...`）：wire VM 是 64 位机，
  无法复现 x86-32 的高 32 位清零与 32 位进位/符号标志，x64 流中一律跳过；
- `CALL`/`RET`/`PUSH`/`POP`/`IMUL`/`movabs`/带 index 的 `LEA` 等解释器不支持的指令。

要真正虚拟化关键函数，使用 `examples/example_vm.S` 的寄存器直通汇编块。
块长需足够容纳运行时 trampoline：约 `51 + 10×保留寄存器数 + 16` 字节；
解释器参数与调用约定固定保留 `rax/rcx/rdx/r8-r11`，因此函数体至少约
137 字节才可能被虚拟化（扫描列表中的「可虚拟化」列即按此估算，打包器按
区域实测做最终判定）。


## 兼容性

旧版 `NOVAPACK_BEGIN` / `NOVAPACK_END` 继续可用，字节模式不变。