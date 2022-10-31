#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/detail/arch/aarch64/ExtensionSupport.cpu-aarch64.h>
#include <AesLib/detail/arch/aarch64/AesDecryptImpl128.cpu-aarch64.h>
#include <AesLib/detail/arch/aarch64/AesEncryptImpl128.cpu-aarch64.h>
#include <AesLib/detail/AesDecryptImpl128.cpu-generic.h>
#include <AesLib/detail/AesEncryptImpl128.cpu-generic.h>
#include <arm_neon.h>

namespace crypto {
namespace detail {

std::unique_ptr<crypto::detail::IAesDecryptor128> BuilderDecryptorImpl(const void* pKey, size_t keySize) {
    /* Check for AES extension support. */
    if(crypto::detail::arch::aarch64::SupportsAesExtensions()) {
        std::make_unique<crypto::detail::arch::aarch64::AesDecryptImpl128>(pKey, keySize);
    }

    return std::make_unique<crypto::detail::AesDecryptImpl128>(pKey, keySize);
}

std::unique_ptr<crypto::detail::IAesEncryptor128> BuilderEncryptorImpl(const void* pKey, size_t keySize) {
    /* Check for AES extension support. */
    if(crypto::detail::arch::aarch64::SupportsAesExtensions()) {
        std::make_unique<crypto::detail::arch::aarch64::AesEncryptImpl128>(pKey, keySize);
    }

    return std::make_unique<crypto::detail::AesEncryptImpl128>(pKey, keySize);
}

} // namespace detail
} // namespace crypto
