#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/AesCommon.h>
#include <wmmintrin.h>

namespace crypto {
namespace detail {

void AesXorBlock128(void* pOut, const void* pIn1, const void* pIn2) {
    ALIGN(16) __m128i block1 = _mm_loadu_si128(static_cast<const __m128i*>(pIn1));
    ALIGN(16) __m128i block2 = _mm_loadu_si128(static_cast<const __m128i*>(pIn2));

    block1 = _mm_xor_si128(block1, block2);

    _mm_storeu_si128(static_cast<__m128i*>(pOut), block1);
}

} // namespace detail
} // namespace crypto
