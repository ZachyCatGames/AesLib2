#include<AesLib/detail/AesImplBuilder.h>
#include <AesLib/detail/AesDecryptImpl128.cpu-generic.h>
#include <AesLib/detail/AesEncryptImpl128.cpu-generic.h>

namespace crypto {
namespace detail {

template<typename... Args>
std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(Args... args) {
    return std::make_unique<crypto::detail::AesDecryptImpl128>(args...);
}

template<typename... Args>
std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(Args... args) {
    return std::make_unique<crypto::detail::AesEncryptImpl128>(args...);
}

template std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor();
template std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(const void* pKey, size_t keySize);

template std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor();
template std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(const void* pKey, size_t keySize);

} // namespace detail
} // namespace crypto
