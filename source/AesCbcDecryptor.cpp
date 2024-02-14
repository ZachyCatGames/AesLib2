#include <AesLib/AesCbcDecryptor.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesCbcDecryptor<KeyLength>::AesCbcDecryptor() :
    detail::AesCbcDecryptorImpl(detail::BuildDecryptor<KeyLength>()) {}

template<int KeyLength>
AesCbcDecryptor<KeyLength>::AesCbcDecryptor(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) :
    detail::AesCbcDecryptorImpl(detail::BuildDecryptor<KeyLength>(pKey, keySize), pIv, ivSize) {}

template<int KeyLength>
AesCbcDecryptor<KeyLength>::~AesCbcDecryptor() = default;

template class AesCbcDecryptor<128>;
template class AesCbcDecryptor<192>;
template class AesCbcDecryptor<256>;

} // namespace crypto
