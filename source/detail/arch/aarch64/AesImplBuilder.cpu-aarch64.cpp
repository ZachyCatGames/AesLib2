#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/detail/arch/aarch64/ExtensionSupport.cpu-aarch64.h>
#include <AesLib/detail/arch/aarch64/AesDecryptImpl128.cpu-aarch64.h>
#include <AesLib/detail/arch/aarch64/AesEncryptImpl128.cpu-aarch64.h>
#include <AesLib/detail/AesDecryptImpl128.cpu-generic.h>
#include <AesLib/detail/AesEncryptImpl128.cpu-generic.h>
#include <arm_neon.h>

namespace crypto {
namespace detail {

template<typename... Args>
std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(Args... args) {
    /* Check for AES extension support. */
    if(crypto::detail::arch::aarch64::SupportsAesExtensions()) {
        std::make_unique<crypto::detail::arch::aarch64::AesDecryptImpl128>(args...);
    }

    return std::make_unique<crypto::detail::AesDecryptImpl128>(args...);
}

template<typename... Args>
std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(Args... args) {
    /* Check for AES extension support. */
    if(crypto::detail::arch::aarch64::SupportsAesExtensions()) {
        std::make_unique<crypto::detail::arch::aarch64::AesEncryptImpl128>(args...);
    }

    return std::make_unique<crypto::detail::AesEncryptImpl128>(args...);
}

template std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(void);
template std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(const void*, size_t);

template std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(void);
template std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(const void*, size_t);

} // namespace detail
} // namespace crypto
