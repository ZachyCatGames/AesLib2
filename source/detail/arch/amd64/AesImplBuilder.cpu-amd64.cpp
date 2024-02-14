#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/detail/arch/amd64/ExtensionSupport.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesDecryptImpl.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesEncryptImpl.cpu-amd64.h>
#include <AesLib/detail/AesDecryptImpl.cpu-generic.h>
#include <AesLib/detail/AesEncryptImpl.cpu-generic.h>

namespace crypto {
namespace detail {

namespace {

template<int KeyLength, typename... Args>
UniqueDecryptor BuildDecryptorImpl(Args... args) {
    /* Check for AES extension support. */
    if(arch::amd64::SupportsAesExtensions())
        return std::make_unique<arch::amd64::AesDecryptImpl<KeyLength>>(args...);

    return std::make_unique<AesDecryptImpl<KeyLength>>(args...);
}

template<int KeyLength, typename... Args>
UniqueEncryptor BuildEncryptorImpl(Args... args) {
    /* Check for AES extension support. */
    if(arch::amd64::SupportsAesExtensions())
        return std::make_unique<arch::amd64::AesEncryptImpl<KeyLength>>(args...);

    return std::make_unique<AesEncryptImpl<KeyLength>>(args...);
}

} // namespace

template<int KeyLength>
UniqueDecryptor BuildDecryptor() { return BuildDecryptorImpl<KeyLength>(); }

template<int KeyLength>
UniqueDecryptor BuildDecryptor(const void* pKey, std::size_t keySize) { return BuildDecryptorImpl<KeyLength>(pKey, keySize); }

template<int KeyLength>
UniqueEncryptor BuildEncryptor() { return BuildEncryptorImpl<KeyLength>(); }

template<int KeyLength>
UniqueEncryptor BuildEncryptor(const void* pKey, std::size_t keySize) { return BuildEncryptorImpl<KeyLength>(pKey, keySize); }

template UniqueDecryptor BuildDecryptor<128>();
template UniqueDecryptor BuildDecryptor<192>();
template UniqueDecryptor BuildDecryptor<256>();

template UniqueDecryptor BuildDecryptor<128>(const void* pKey, std::size_t keySize);
template UniqueDecryptor BuildDecryptor<192>(const void* pKey, std::size_t keySize);
template UniqueDecryptor BuildDecryptor<256>(const void* pKey, std::size_t keySize);

template UniqueEncryptor BuildEncryptor<128>();
template UniqueEncryptor BuildEncryptor<192>();
template UniqueEncryptor BuildEncryptor<256>();

template UniqueEncryptor BuildEncryptor<128>(const void* pKey, std::size_t keySize);
template UniqueEncryptor BuildEncryptor<192>(const void* pKey, std::size_t keySize);
template UniqueEncryptor BuildEncryptor<256>(const void* pKey, std::size_t keySize);

} // namespace detail
} // namespace crypto
