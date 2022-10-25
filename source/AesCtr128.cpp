#include <AesLib/AesCtr128.h>
#include <AesLib/detail/AesXorBlock128.h>

namespace crypto {

AesCtr128::AesCtr128() = default;

AesCtr128::AesCtr128(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize) :
    m_EcbEncrypter(pKey, keySize)
{
    std::memcpy(m_AesCounter, pCtr, 0x10);
}

AesCtr128::~AesCtr128() = default;

void AesCtr128::SetCounter(const void* pCtr, size_t ctrSize) {
    std::memcpy(m_AesCounter, pCtr, 0x10);
}

crypto::AesResult AesCtr128::CryptBlock(void* pOut, const void* pIn) {
    uint8_t ctr[Aes128BlockLength];
    uint8_t tmp[Aes128BlockLength];

    /* Copy iv to ctr */
    std::memcpy(ctr, m_AesCounter, Aes128BlockLength);

    /* Encrypt CTR with key */
    m_EcbEncrypter.EncryptBlock(tmp, ctr);

    /* XOR Data with encrypted CTR */
    crypto::detail::AesXorBlock128(pOut, pIn, tmp);

    /* Return */
    return crypto::AesResult::Success;
}

// TODO: Sort out lengthLeft/pos bs.
crypto::AesResult AesCtr128::CryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    uint8_t tmp[Aes128BlockLength];
    int64_t lengthLeft = inSize;
    int64_t pos = 0;

    while(lengthLeft > 0) {
        /* Encrypt CTR with key */
        m_EcbEncrypter.EncryptBlock(tmp, m_AesCounter);

        /* XOR Data with encrypted CTR */
        crypto::detail::AesXorBlock128(static_cast<uint8_t*>(pOut) + pos, static_cast<const uint8_t*>(pIn) + pos, tmp);
    
        /* Increment CTR */
        for(uint8_t i = Aes128BlockLength - 1; i >= 0; i--) {
            m_AesCounter[i]++;
            if(m_AesCounter[i])
                break;
        }

        /* Increment Position */
        lengthLeft -= Aes128BlockLength;
        pos        += Aes128BlockLength;
    }

    /* Return */
    return crypto::AesResult::Success;
}

} // namespace crypto
