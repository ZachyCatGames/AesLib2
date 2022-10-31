#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/detail/arch/amd64/ExtensionSupport.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesDecryptImpl128.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesEncryptImpl128.cpu-amd64.h>
#include <AesLib/detail/AesDecryptImpl128.cpu-generic.h>
#include <AesLib/detail/AesEncryptImpl128.cpu-generic.h>

namespace crypto {
namespace detail {

std::unique_ptr<crypto::detail::IAesDecryptor128> BuilderDecryptorImpl(const void* pKey, size_t keySize) {
    /* Check for AES extension support. */
    if(crypto::detail::arch::amd64::SupportsAesExtensions())
        return std::make_unique<crypto::detail::arch::amd64::AesDecryptImpl128>(pKey, keySize);

    return std::make_unique<crypto::detail::AesDecryptImpl128>(pKey, keySize);
}

std::unique_ptr<crypto::detail::IAesEncryptor128> BuilderEncryptorImpl(const void* pKey, size_t keySize) {
    /* Check for AES extension support. */
    if(crypto::detail::arch::amd64::SupportsAesExtensions())
        return std::make_unique<crypto::detail::arch::amd64::AesEncryptImpl128>(pKey, keySize);

    return std::make_unique<crypto::detail::AesEncryptImpl128>(pKey, keySize);
}

} // namespace detail
} // namespace crypto
