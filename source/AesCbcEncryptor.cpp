#include <AesLib/AesCbcEncryptor.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesCbcEncryptor<KeyLength>::AesCbcEncryptor() :
    detail::AesCbcEncryptorImpl(detail::BuildEncryptor<KeyLength>()) {}

template<int KeyLength>
AesCbcEncryptor<KeyLength>::AesCbcEncryptor(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) :
    detail::AesCbcEncryptorImpl(detail::BuildEncryptor<KeyLength>(pKey, keySize), pIv, ivSize) {}

template<int KeyLength>
AesCbcEncryptor<KeyLength>::~AesCbcEncryptor() = default;

template class AesCbcEncryptor<128>;
template class AesCbcEncryptor<192>;
template class AesCbcEncryptor<256>;

} // namespace crypto
