#include <AesLib/AesCtr128.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

AesCtr128::AesCtr128() :
    m_pEncryptor(crypto::detail::BuildEncryptor())
{
    /* ... */
}

AesCtr128::AesCtr128(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize) :
    m_pEncryptor(crypto::detail::BuildEncryptor(pKey, keySize))
{
    std::memcpy(m_AesCounter, pCtr, 0x10);
}

AesCtr128::~AesCtr128() = default;

void AesCtr128::Initialize(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize) {
    m_pEncryptor->Initialize(pKey, keySize);

    std::memcpy(m_AesCounter, pCtr, 0x10);
}

void AesCtr128::Finalize() {
    m_pEncryptor->Finalize();
}

void AesCtr128::SetCounter(const void* pCtr, size_t ctrSize) {
    std::memcpy(m_AesCounter, pCtr, 0x10);
}

crypto::AesResult AesCtr128::CryptBlock(void* pOut, const void* pIn) {
    uint8_t tmp[Aes128BlockLength];

    /* Encrypt CTR with key */
    m_pEncryptor->EncryptBlock(tmp, m_AesCounter);

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
        m_pEncryptor->EncryptBlock(tmp, m_AesCounter);

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
