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

## 重要约束

VM 解释器只处理纯寄存器、直线型 x86-64 子集。区域一旦访问 `RSP`/`RBP` 或内存，会安全地保留为原生代码。要真正虚拟化关键函数，使用 `examples/example_vm.S` 的寄存器直通汇编块，且块长需足够容纳运行时 trampoline（约 51 + 10×寄存器数 字节）。

## 兼容性

旧版 `NOVAPACK_BEGIN` / `NOVAPACK_END` 继续可用，字节模式不变。