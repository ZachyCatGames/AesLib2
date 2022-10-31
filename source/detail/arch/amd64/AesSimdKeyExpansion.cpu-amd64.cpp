#include <AesLib/detail/arch/amd64/AesSimdKeyExpansion.cpu-amd64.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

__m128i PerformSimdKeyExpansion(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
