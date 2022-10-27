#pragma once
#include <AesLib/AesCommon.h>
#include <cstdio>

namespace crypto {
namespace detail {

class AesDecryptImpl128 {
public:
    AesDecryptImpl128();
    AesDecryptImpl128(const void* pKey, size_t keySize);
    ~AesDecryptImpl128();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    void DecryptBlock(void* pOut, const void* pIn);

private:
    void ExpandKeyImpl();

private:
    uint8_t m_RoundKeys[11][16];
    uint32_t m_InvRoundKeys[11][4];
};

} // namespace detail
} // namespace crypto
