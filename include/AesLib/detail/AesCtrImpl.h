#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <cstdint>

namespace crypto {
namespace detail {

class AesCtrImpl {
public:
    static constexpr int CtrSize = AesBlockLength;
public:
    AesCtrImpl(UniqueEncryptor&& pEnc);
    AesCtrImpl(UniqueEncryptor&& pEnc, const void* pCtr, size_t ctrSize);
    ~AesCtrImpl();

    void Initialize(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize);
    void Finalize();

    /* Set counter. */
    void SetCounter(const void* pCtr, size_t ctrSize);

    /* CTR Crypt Block */
    AesResult CryptBlock(void* pOut, const void* pIn);

    /* CTR Crypt Data */
    AesResult CryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);
private:
    UniqueEncryptor m_pEncryptor;
    uint8_t m_Counter[16];
}; // class AesCtrImpl

} // namespace detail
} // namespace crypto
