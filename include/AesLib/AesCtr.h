#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <cstdint>
#include <memory>

namespace crypto {

template<int KeyLength>
class AesCtr {
public:
    static constexpr int KeySize = KeyLength / 8;
    static constexpr int CtrSize = AesBlockLength;

public:
    AesCtr();
    AesCtr(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize);
    ~AesCtr();

    void Initialize(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize);
    void Finalize();

    /* Set counter. */
    void SetCounter(const void* pCtr, size_t ctrSize);

    /* CTR Crypt Block */
    AesResult CryptBlock(void* pOut, const void* pIn);

    /* CTR Crypt Data */
    AesResult CryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);

private:
    std::unique_ptr<detail::IAesEncryptor<KeyLength>> m_pEncryptor;
    uint8_t m_AesCounter[16];
};

using AesCtr128 = AesCtr<128>;
using AesCtr192 = AesCtr<192>;
using AesCtr256 = AesCtr<256>;

} // namespace crypto
