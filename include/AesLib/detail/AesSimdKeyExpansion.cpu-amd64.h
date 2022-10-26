#pragma once
#include <wmmintrin.h>

namespace crypto {
namespace detail {

#define AES_128_key_exp(k, rcon) ::crypto::detail::PerformSimdKeyExpansion(k, _mm_aeskeygenassist_si128(k, rcon))

__m128i PerformSimdKeyExpansion(__m128i key, __m128i keygened);

} // namespace detail
} // namespace crypto

