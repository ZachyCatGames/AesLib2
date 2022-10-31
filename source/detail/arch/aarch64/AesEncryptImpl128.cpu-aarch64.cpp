#include <AesLib/detail/arch/aarch64/AesEncryptImpl128.cpu-aarch64.h>

namespace crypto {
namespace detail {
namespace arch {
namespace aarch64 {

AesEncryptImpl128::AesEncryptImpl128() = default;

AesEncryptImpl128::AesEncryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesEncryptImpl128::~AesEncryptImpl128() = default;

void AesEncryptImpl128::Finalize() {
    /* ... */
}

} // namespace aarch64
} // namespace arch
} // namespace detail
} // namespace crypto
