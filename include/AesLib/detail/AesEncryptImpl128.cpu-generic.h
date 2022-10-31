#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor128.h>
#include <cstdio>

namespace crypto {
namespace detail {

class AesEncryptImpl128 : public crypto::detail::IAesEncryptor128 {
public:
    AesEncryptImpl128();
    AesEncryptImpl128(const void* pKey, size_t keySize);
    virtual ~AesEncryptImpl128();

    virtual void Initialize(const void* pKey, size_t keySize);
    virtual void Finalize();

    virtual void EncryptBlock(void* pOut, const void* pIn);

private:
    uint32_t m_RoundKeys[11][4];
};

} // namespace detail
} // namespace crypto
