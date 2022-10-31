#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/detail/arch/amd64/ExtensionSupport.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesDecryptImpl128.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesEncryptImpl128.cpu-amd64.h>
#include <AesLib/detail/AesDecryptImpl128.cpu-generic.h>
#include <AesLib/detail/AesEncryptImpl128.cpu-generic.h>

namespace crypto {
namespace detail {

template<typename... Args>
std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(Args... args) {
    /* Check for AES extension support. */
    if(crypto::detail::arch::amd64::SupportsAesExtensions())
        return std::make_unique<crypto::detail::arch::amd64::AesDecryptImpl128>(args...);

    return std::make_unique<crypto::detail::AesDecryptImpl128>(args...);
}

template<typename... Args>
std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(Args... args) {
    /* Check for AES extension support. */
    if(crypto::detail::arch::amd64::SupportsAesExtensions())
        return std::make_unique<crypto::detail::arch::amd64::AesEncryptImpl128>(args...);

    return std::make_unique<crypto::detail::AesEncryptImpl128>(args...);
}

template std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(void);
template std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(const void*, size_t);

template std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(void);
template std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(const void*, size_t);

} // namespace detail
} // namespace crypto
