#include <AesLib/AesEcbEncryptor.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesEcbEncryptor<KeyLength>::AesEcbEncryptor() :
    detail::AesEcbEncryptorImpl(detail::BuildEncryptor<KeyLength>()) {}

template<int KeyLength>
AesEcbEncryptor<KeyLength>::AesEcbEncryptor(const void* pKey, size_t keySize) :
    detail::AesEcbEncryptorImpl(detail::BuildEncryptor<KeyLength>(pKey, keySize)) {}

template<int KeyLength>
AesEcbEncryptor<KeyLength>::~AesEcbEncryptor() = default;

template class AesEcbEncryptor<128>;
template class AesEcbEncryptor<192>;
template class AesEcbEncryptor<256>;

} // namespace crypto
