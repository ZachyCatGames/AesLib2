#include <AesLib/AesEcbDecryptor.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesEcbDecryptor<KeyLength>::AesEcbDecryptor() :
    detail::AesEcbDecryptorImpl(detail::BuildDecryptor<KeyLength>()) {}

template<int KeyLength>
AesEcbDecryptor<KeyLength>::AesEcbDecryptor(const void* pKey, size_t keySize) :
    detail::AesEcbDecryptorImpl(detail::BuildDecryptor<KeyLength>(pKey, keySize)) {}

template<int KeyLength>
AesEcbDecryptor<KeyLength>::~AesEcbDecryptor() = default;

template class AesEcbDecryptor<128>;
template class AesEcbDecryptor<192>;
template class AesEcbDecryptor<256>;

} // namespace crypto
