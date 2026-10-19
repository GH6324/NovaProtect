#pragma once

namespace np {
// Shipping core is never a CLI API. The genuine UI authorizes a single process
// through a same-user pipe whose OS-reported server PID is manifest-bound.
void requireClientInvocation();
[[noreturn]] void failClosed();
}
