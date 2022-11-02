#include <AesLib/AesCbcDecryptor.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesCbcDecryptor<KeyLength>::AesCbcDecryptor() :
    m_pDecryptor(crypto::detail::BuildDecryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength>
AesCbcDecryptor<KeyLength>::AesCbcDecryptor(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) :
    m_pDecryptor(crypto::detail::BuildDecryptor<KeyLength>(pKey, keySize))
{
    std::memcpy(m_AesIv, pIv, crypto::AesBlockLength);
}

template<int KeyLength>
AesCbcDecryptor<KeyLength>::~AesCbcDecryptor() = default;

template<int KeyLength>
void AesCbcDecryptor<KeyLength>::Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) {
    /* Initialize ECB encrypter. */
    m_pDecryptor->Initialize(pKey, keySize);

    /* Copy iv. */
    std::memcpy(m_AesIv, pIv, crypto::AesBlockLength);
}

template<int KeyLength>
void AesCbcDecryptor<KeyLength>::Finalize() {
    /* Finalize ECB encrypter. */
    m_pDecryptor->Finalize();
}

template<int KeyLength>
crypto::AesResult AesCbcDecryptor<KeyLength>::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t size) {
    uint8_t tmp[crypto::AesBlockLength];
    uint8_t nextIv[crypto::AesBlockLength];

    /* Assert that data is aligned to 0x10 bytes */
    if(size % crypto::AesBlockLength != 0) {
        return crypto::AesResult::NotAligned;
    }

    /* Loop until all data is decrypted */
    for(size_t pos = 0; pos < size; pos += crypto::AesBlockLength) {
        /* Copy encrypted data to next iv */
        std::memcpy(nextIv, static_cast<const uint8_t*>(pIn) + pos, crypto::AesBlockLength);

        /* Decrypt data with key */
        m_pDecryptor->DecryptBlock(tmp, static_cast<const uint8_t*>(pIn) + pos);

        /* XOR data with iv */
        crypto::detail::AesXorBlock128(static_cast<uint8_t*>(pOut) + pos, tmp, m_AesIv);

        /* Copy next iv to iv */
        std::memcpy(m_AesIv, nextIv, crypto::AesBlockLength);
    }

    /* Return */
    return crypto::AesResult::Success;
}

template class AesCbcDecryptor<128>;
template class AesCbcDecryptor<192>;
template class AesCbcDecryptor<256>;

} // namespace crypto
