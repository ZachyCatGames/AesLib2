#pragma once
#include <wmmintrin.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

#define AES_128_key_exp(k, rcon) ::crypto::detail::arch::amd64::PerformSimdKeyExpansion(k, _mm_aeskeygenassist_si128(k, rcon))

__m128i PerformSimdKeyExpansion(__m128i key, __m128i keygened);

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto

