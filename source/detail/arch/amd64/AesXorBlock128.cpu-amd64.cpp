#include <AesLib/detail/AesXorBlock128.h>
#include <wmmintrin.h>

namespace crypto {
namespace detail {

void AesXorBlock128(void* pOut, const void* pIn1, const void* pIn2) {
    *static_cast<__m128i*>(pOut) = _mm_xor_si128(*static_cast<const __m128i*>(pIn1), *static_cast<const __m128i*>(pIn2));
}

} // namespace detail
} // namespace crypto
