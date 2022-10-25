#pragma once
#include <AesLib/AesCommon.h>
#include <cstdio>
#include <wmmintrin.h>

namespace crypto {
namespace detail {

class AesEncryptImpl128 {
public:
    AesEncryptImpl128();
    AesEncryptImpl128(const void* pKey, size_t keySize);
    ~AesEncryptImpl128();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    void EncryptBlock(void* pOut, const void* pIn);

private:
    void ExpandKeyImpl();

private:
    __m128i m_RoundKeys[11];
};

} // namespace detail
} // namespace crypto
