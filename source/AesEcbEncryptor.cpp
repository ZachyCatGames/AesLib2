#include <AesLib/AesEcbEncryptor.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesEcbEncryptor<KeyLength>::AesEcbEncryptor() :
    m_pImpl(detail::BuildEncryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength>
AesEcbEncryptor<KeyLength>::AesEcbEncryptor(const void* pKey, size_t keySize) :
    m_pImpl(detail::BuildEncryptor<KeyLength>(pKey, keySize))
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
AesResult AesEcbEncryptor<KeyLength>::EncryptBlock(void* pOut, const void* pIn) {
    m_pImpl->EncryptBlock(static_cast<uint8_t*>(pOut), static_cast<const uint8_t*>(pIn));

    return AesResult::Success;
}

template<int KeyLength>
AesResult AesEcbEncryptor<KeyLength>::EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    /* Compare in/out sizes. */
    if(outSize < inSize)
        return AesResult::OutTooSmall;

    /* Check alignment. */
    if(inSize % AesBlockLength)
        return AesResult::NotAligned;

    for(size_t i = 0; i < inSize; i += AesBlockLength) {
        m_pImpl->EncryptBlock(static_cast<uint8_t*>(pOut) + i, static_cast<const uint8_t*>(pIn) + i);
    }

    return AesResult::Success;
}

template class AesEcbEncryptor<128>;
template class AesEcbEncryptor<192>;
template class AesEcbEncryptor<256>;

} // namespace crypto
