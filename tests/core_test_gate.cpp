// Test-only link replacement. Never compiled by build.ps1 or distributed.
// Exercising the packer regression does not create a shipping invocation bypass.
#include "../include/client_gate.h"
#include <cstdlib>
namespace np {
void requireClientInvocation() {}
[[noreturn]] void failClosed() { std::abort(); }
}
