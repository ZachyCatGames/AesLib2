#include <AesLib/detail/AesXorBlock128.h>

namespace crypto {
namespace detail {

void AesXorBlock128(void* pOut, const void* pIn1, const void* pIn2) {
    for(int i = 0; i < 4; ++i) {
        static_cast<uint32_t*>(pOut)[i] = static_cast<const uint32_t*>(pIn1)[i] ^ static_cast<const uint32_t*>(pIn2)[i];
    }
}

} // namespace detail
} // namespace crypto
