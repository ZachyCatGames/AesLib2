#pragma once
#include <AesLib/AesCommon.h>
#include <cstdio>

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
    uint8_t m_RoundKeys[11][16];
};

} // namespace detail
} // namespace crypto
