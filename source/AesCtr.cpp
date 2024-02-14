#include <AesLib/AesCtr.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesCtr<KeyLength>::AesCtr() :
    detail::AesCtrImpl(detail::BuildEncryptor<KeyLength>()) {}

template<int KeyLength>
AesCtr<KeyLength>::AesCtr(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize) :
    detail::AesCtrImpl(detail::BuildEncryptor<KeyLength>(pKey, keySize), pCtr, ctrSize) {}

template<int KeyLength>
AesCtr<KeyLength>::~AesCtr() = default;

template class AesCtr<128>;
template class AesCtr<192>;
template class AesCtr<256>;

} // namespace crypto
