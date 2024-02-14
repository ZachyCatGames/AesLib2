#include <AesLib/detail/AesCtrImpl.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {
namespace detail {

AesCtrImpl::AesCtrImpl(UniqueEncryptor&& pEnc) :
    m_pEncryptor(std::move(pEnc)) {}

AesCtrImpl::AesCtrImpl(UniqueEncryptor&& pEnc, const void* pCtr, size_t ctrSize) :
    m_pEncryptor(std::move(pEnc))
{
    std::memcpy(m_Counter, pCtr, CtrSize);
}

AesCtrImpl::~AesCtrImpl() = default;

void AesCtrImpl::Initialize(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize) {
    m_pEncryptor->Initialize(pKey, keySize);
    std::memcpy(m_Counter, pCtr, CtrSize);
}

void AesCtrImpl::Finalize() {
    m_pEncryptor->Finalize();
}

void AesCtrImpl::SetCounter(const void* pCtr, size_t ctrSize) {
    std::memcpy(m_Counter, pCtr, CtrSize);
}

AesResult AesCtrImpl::CryptBlock(void* pOut, const void* pIn) {
    uint8_t tmp[AesBlockLength];

    /* Encrypt CTR with key */
    m_pEncryptor->EncryptBlock(tmp, m_Counter);

    /* XOR Data with encrypted CTR */
    detail::AesXorBlock128(pOut, pIn, tmp);

    /* Return */
    return AesResult::Success;
}

// TODO: Sort out lengthLeft/pos bs.

AesResult AesCtrImpl::CryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    uint8_t tmp[AesBlockLength];
    int64_t lengthLeft = inSize;
    int64_t pos = 0;

    while(lengthLeft > 0) {
        /* Encrypt CTR with key */
        m_pEncryptor->EncryptBlock(tmp, m_Counter);

        /* XOR Data with encrypted CTR */
        detail::AesXorBlock128(static_cast<uint8_t*>(pOut) + pos, static_cast<const uint8_t*>(pIn) + pos, tmp);
    
        /* Increment CTR */
        for(uint8_t i = AesBlockLength - 1; i >= 0; i--) {
            m_Counter[i]++;
            if(m_Counter[i])
                break;
        }

        /* Increment Position */
        lengthLeft -= AesBlockLength;
        pos        += AesBlockLength;
    }

    /* Return */
    return AesResult::Success;
}

} // namespace detail
} // namespace crypto
