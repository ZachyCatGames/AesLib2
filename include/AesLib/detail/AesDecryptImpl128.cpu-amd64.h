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
    void ExpandKeyImpl(const void* pKey);

private:
    uint8_t m_InvRoundKeyStorage[13][16];
};

} // namespace detail
} // namespace crypto
