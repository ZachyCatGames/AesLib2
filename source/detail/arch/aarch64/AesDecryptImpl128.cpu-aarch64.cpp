#include <AesLib/detail/arch/aarch64/AesDecryptImpl128.cpu-aarch64.h>

namespace crypto {
namespace detail {
namespace arch {
namespace aarch64 {

AesDecryptImpl128::AesDecryptImpl128() = default;

AesDecryptImpl128::AesDecryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesDecryptImpl128::~AesDecryptImpl128() = default;


void AesDecryptImpl128::Finalize() {
    /* ... */
}

} // namespace aarch64
} // namespace arch
} // namespace detail
} // namespace crypto
