#pragma once
#include <cstdint>

namespace crypto {
namespace detail {

void AesXorBlock128(void* pOut, const void* pIn1, const void* pIn2);

} // namespace detail
} // namespace crypto
