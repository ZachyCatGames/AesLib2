#pragma once
#include <AesLib/AesCommon.h>
#include <cstdio>

namespace crypto {
namespace detail {

class AesEcbDecryptor128 {
public:
    AesEcbDecryptor128();
    AesEcbDecryptor128(const void* pKey, size_t keySize);
    ~AesEcbDecryptor128();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    crypto::AesResult DecryptBlock(void* pOut, const void* pIn);
    crypto::AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);

private:
    void ExpandKeyImpl();
    void DecryptBlockImpl(uint8_t* pOut, const uint8_t* pIn);

private:
    uint8_t m_RoundKeys[11][16];
};

} // namespace detail
} // namespace crypto
