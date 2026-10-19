#pragma once
// NovaProtect multi-layer encryption (crypto_layers.cpp)
#include <cstdint>
#include <cstddef>

namespace np {

// Three-layer encryption: RC4 + XOR + additive rotation.
// `nonce` should be random per region; `seed` is typically the region RVA.
// Both functions are deterministic: same (nonce, seed) always produce the
// same result, and layeredDecrypt(layeredEncrypt(x)) == x.
void layeredEncrypt(uint8_t* data, size_t len, uint32_t nonce, uint32_t seed);
void layeredDecrypt(uint8_t* data, size_t len, uint32_t nonce, uint32_t seed);

} // namespace np