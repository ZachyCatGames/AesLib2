#pragma once
#include <AesLib/AesCommon.h>
#include <cstdio>
#include <wmmintrin.h>

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
    __m128i m_RoundKeys[11];
    __m128i m_InvRoundKeys[11];
};

} // namespace detail
} // namespace crypto
