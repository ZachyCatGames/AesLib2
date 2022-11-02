#include <AesLib/AesEcbEncryptor.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesEcbEncryptor<KeyLength>::AesEcbEncryptor() :
    m_pImpl(crypto::detail::BuildEncryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength>
AesEcbEncryptor<KeyLength>::AesEcbEncryptor(const void* pKey, size_t keySize) :
    m_pImpl(crypto::detail::BuildEncryptor<KeyLength>(pKey, keySize))
{
    /* ... */
}

template<int KeyLength>
AesEcbEncryptor<KeyLength>::~AesEcbEncryptor() = default;

template<int KeyLength>
void AesEcbEncryptor<KeyLength>::Initialize(const void* pKey, size_t keySize) {
    m_pImpl->Initialize(pKey, keySize);
}

template<int KeyLength>
void AesEcbEncryptor<KeyLength>::Finalize() {
    /* ... */
}

template<int KeyLength>
crypto::AesResult AesEcbEncryptor<KeyLength>::EncryptBlock(void* pOut, const void* pIn) {
    m_pImpl->EncryptBlock(static_cast<uint8_t*>(pOut), static_cast<const uint8_t*>(pIn));

    return crypto::AesResult::Success;
}

template<int KeyLength>
crypto::AesResult AesEcbEncryptor<KeyLength>::EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    /* Compare in/out sizes. */
    if(outSize < inSize)
        return crypto::AesResult::OutTooSmall;

    /* Check alignment. */
    if(inSize % crypto::AesBlockLength)
        return crypto::AesResult::NotAligned;

    for(size_t i = 0; i < inSize; i += crypto::AesBlockLength) {
        m_pImpl->EncryptBlock(static_cast<uint8_t*>(pOut) + i, static_cast<const uint8_t*>(pIn) + i);
    }

    return crypto::AesResult::Success;
}

template class AesEcbEncryptor<128>;
template class AesEcbEncryptor<192>;
template class AesEcbEncryptor<256>;

} // namespace crypto
