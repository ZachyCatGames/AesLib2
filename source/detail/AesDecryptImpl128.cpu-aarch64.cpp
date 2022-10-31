#include <AesLib/detail/AesDecryptImpl128.cpu-aarch64.h>
#include <AesLib/detail/AesExpandKeyImpl128.h>

namespace crypto {
namespace detail {

AesDecryptImpl128::AesDecryptImpl128() = default;

AesDecryptImpl128::AesDecryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesDecryptImpl128::~AesDecryptImpl128() = default;


void AesDecryptImpl128::Finalize() {
    /* ... */
}

} // namespace detail
} // namespace crypto
