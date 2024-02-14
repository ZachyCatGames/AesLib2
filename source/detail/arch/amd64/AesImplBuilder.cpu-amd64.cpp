#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/detail/arch/amd64/ExtensionSupport.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesDecryptImpl.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesEncryptImpl.cpu-amd64.h>
#include <AesLib/detail/AesDecryptImpl.cpu-generic.h>
#include <AesLib/detail/AesEncryptImpl.cpu-generic.h>

namespace crypto {
namespace detail {

template<int KeyLength, typename... Args>
std::unique_ptr<IAesDecryptor<KeyLength>> BuildDecryptor(Args... args) {
    /* Check for AES extension support. */
    if(arch::amd64::SupportsAesExtensions())
        return std::make_unique<arch::amd64::AesDecryptImpl<KeyLength>>(args...);

    return std::make_unique<AesDecryptImpl<KeyLength>>(args...);
}

template<int KeyLength, typename... Args>
std::unique_ptr<IAesEncryptor<KeyLength>> BuildEncryptor(Args... args) {
    /* Check for AES extension support. */
    if(arch::amd64::SupportsAesExtensions())
        return std::make_unique<arch::amd64::AesEncryptImpl<KeyLength>>(args...);

    return std::make_unique<AesEncryptImpl<KeyLength>>(args...);
}

template std::unique_ptr<IAesDecryptor<128>> BuildDecryptor(void);
template std::unique_ptr<IAesDecryptor<128>> BuildDecryptor(const void*, size_t);
template std::unique_ptr<IAesDecryptor<192>> BuildDecryptor(void);
template std::unique_ptr<IAesDecryptor<192>> BuildDecryptor(const void*, size_t);
template std::unique_ptr<IAesDecryptor<256>> BuildDecryptor(void);
template std::unique_ptr<IAesDecryptor<256>> BuildDecryptor(const void*, size_t);

template std::unique_ptr<IAesEncryptor<128>> BuildEncryptor(void);
template std::unique_ptr<IAesEncryptor<128>> BuildEncryptor(const void*, size_t);
template std::unique_ptr<IAesEncryptor<192>> BuildEncryptor(void);
template std::unique_ptr<IAesEncryptor<192>> BuildEncryptor(const void*, size_t);
template std::unique_ptr<IAesEncryptor<256>> BuildEncryptor(void);
template std::unique_ptr<IAesEncryptor<256>> BuildEncryptor(const void*, size_t);

} // namespace detail
} // namespace crypto
