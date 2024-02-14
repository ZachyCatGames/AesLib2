#include <AesLib/AesCbcEncryptor.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesCbcEncryptor<KeyLength>::AesCbcEncryptor() :
    m_pEncryptor(detail::BuildEncryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength>
AesCbcEncryptor<KeyLength>::AesCbcEncryptor(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) :
    m_pEncryptor(detail::BuildEncryptor<KeyLength>(pKey, keySize))
{
    std::memcpy(m_AesIv, pIv, AesBlockLength);
}

template<int KeyLength>
AesCbcEncryptor<KeyLength>::~AesCbcEncryptor() = default;

template<int KeyLength>
void AesCbcEncryptor<KeyLength>::Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) {
    /* Initialize ECB encrypter. */
    m_pEncryptor->Initialize(pKey, keySize);

    /* Copy iv. */
    std::memcpy(m_AesIv, pIv, AesBlockLength);
}

template<int KeyLength>
void AesCbcEncryptor<KeyLength>::Finalize() {
    /* Finalize ECB encrypter. */
    m_pEncryptor->Finalize();
}

template<int KeyLength>
AesResult AesCbcEncryptor<KeyLength>::EncryptData(void* pOut, size_t outSize, const void* pIn, size_t size) {
    uint8_t tmp[AesBlockLength];

    /* Assert that data is aligned to 0x10 bytes */
    if(size % AesBlockLength != 0) {
        return AesResult::NotAligned;
    }

    /* Loop until all data is encrypted */
    for(size_t pos = 0; pos < size; pos += AesBlockLength) {
        /* Copy input at current position */
        std::memcpy(tmp, static_cast<const uint8_t*>(pIn) + pos, AesBlockLength);

        /* XOR Input with IV */
        detail::AesXorBlock128(tmp, tmp, m_AesIv);

        /* Encrypt data with key */
        m_pEncryptor->EncryptBlock(static_cast<uint8_t*>(pOut) + pos, tmp);

        /* Copy encrypted data to iv_buf */
        std::memcpy(m_AesIv, static_cast<uint8_t*>(pOut) + pos, AesBlockLength);
    }

    /* Return */
    return AesResult::Success;
}

template class AesCbcEncryptor<128>;
template class AesCbcEncryptor<192>;
template class AesCbcEncryptor<256>;

} // namespace crypto
