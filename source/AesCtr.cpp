#include <AesLib/AesCtr.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesCtr<KeyLength>::AesCtr() :
    m_pEncryptor(detail::BuildEncryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength>
AesCtr<KeyLength>::AesCtr(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize) :
    m_pEncryptor(detail::BuildEncryptor<KeyLength>(pKey, keySize))
{
    std::memcpy(m_AesCounter, pCtr, CtrSize);
}

template<int KeyLength>
AesCtr<KeyLength>::~AesCtr() = default;

template<int KeyLength>
void AesCtr<KeyLength>::Initialize(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize) {
    m_pEncryptor->Initialize(pKey, keySize);

    std::memcpy(m_AesCounter, pCtr, CtrSize);
}

template<int KeyLength>
void AesCtr<KeyLength>::Finalize() {
    m_pEncryptor->Finalize();
}

template<int KeyLength>
void AesCtr<KeyLength>::SetCounter(const void* pCtr, size_t ctrSize) {
    std::memcpy(m_AesCounter, pCtr, CtrSize);
}

template<int KeyLength>
AesResult AesCtr<KeyLength>::CryptBlock(void* pOut, const void* pIn) {
    uint8_t tmp[AesBlockLength];

    /* Encrypt CTR with key */
    m_pEncryptor->EncryptBlock(tmp, m_AesCounter);

    /* XOR Data with encrypted CTR */
    detail::AesXorBlock128(pOut, pIn, tmp);

    /* Return */
    return AesResult::Success;
}

// TODO: Sort out lengthLeft/pos bs.
template<int KeyLength>
AesResult AesCtr<KeyLength>::CryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    uint8_t tmp[AesBlockLength];
    int64_t lengthLeft = inSize;
    int64_t pos = 0;

    while(lengthLeft > 0) {
        /* Encrypt CTR with key */
        m_pEncryptor->EncryptBlock(tmp, m_AesCounter);

        /* XOR Data with encrypted CTR */
        detail::AesXorBlock128(static_cast<uint8_t*>(pOut) + pos, static_cast<const uint8_t*>(pIn) + pos, tmp);
    
        /* Increment CTR */
        for(uint8_t i = AesBlockLength - 1; i >= 0; i--) {
            m_AesCounter[i]++;
            if(m_AesCounter[i])
                break;
        }

        /* Increment Position */
        lengthLeft -= AesBlockLength;
        pos        += AesBlockLength;
    }

    /* Return */
    return AesResult::Success;
}

template class AesCtr<128>;
template class AesCtr<192>;
template class AesCtr<256>;

} // namespace crypto
