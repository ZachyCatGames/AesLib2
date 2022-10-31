#pragma once
#include <intrin.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

bool SupportsAesExtensions() {
    int registers[4];
    
    __cpuid(registers, 1);

    return registers[0];
}

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
