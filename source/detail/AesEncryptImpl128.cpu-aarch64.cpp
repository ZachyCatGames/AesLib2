#include <AesLib/detail/AesEncryptImpl128.cpu-aarch64.h>
#include <AesLib/detail/AesExpandKeyImpl128.h>

namespace crypto {
namespace detail {

AesEncryptImpl128::AesEncryptImpl128() = default;

AesEncryptImpl128::AesEncryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesEncryptImpl128::~AesEncryptImpl128() = default;

void AesEncryptImpl128::Finalize() {
    /* ... */
}

} // namespace detail
} // namespace crypto
