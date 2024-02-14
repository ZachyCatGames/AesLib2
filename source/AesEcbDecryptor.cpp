#include <AesLib/AesEcbDecryptor.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesEcbDecryptor<KeyLength>::AesEcbDecryptor() :
    m_pImpl(detail::BuildDecryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength>
AesEcbDecryptor<KeyLength>::AesEcbDecryptor(const void* pKey, size_t keySize) :
    m_pImpl(detail::BuildDecryptor<KeyLength>(pKey, keySize))
{
    /* ... */
}

template<int KeyLength>
AesEcbDecryptor<KeyLength>::~AesEcbDecryptor() = default;

template<int KeyLength>
void AesEcbDecryptor<KeyLength>::Initialize(const void* pKey, size_t keySize) {
    m_pImpl->Initialize(pKey, keySize);
}

template<int KeyLength>
void AesEcbDecryptor<KeyLength>::Finalize() {
    /* ... */
}

template<int KeyLength>
AesResult AesEcbDecryptor<KeyLength>::DecryptBlock(void* pOut, const void* pIn) {
    m_pImpl->DecryptBlock(static_cast<uint8_t*>(pOut), static_cast<const uint8_t*>(pIn));

    return AesResult::Success;
}

template<int KeyLength>
AesResult AesEcbDecryptor<KeyLength>::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    /* Compare in/out sizes. */
    if(outSize < inSize)
        return AesResult::OutTooSmall;

    /* Check alignment. */
    if(inSize % AesBlockLength)
        return AesResult::NotAligned;

    for(size_t i = 0; i < inSize; i += AesBlockLength) {
        m_pImpl->DecryptBlock(static_cast<uint8_t*>(pOut) + i, static_cast<const uint8_t*>(pIn) + i);
    }

    return AesResult::Success;
}

template class AesEcbDecryptor<128>;
template class AesEcbDecryptor<192>;
template class AesEcbDecryptor<256>;

} // namespace crypto
