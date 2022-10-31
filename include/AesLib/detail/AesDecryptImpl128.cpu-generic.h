#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor128.h>
#include <cstdio>

namespace crypto {
namespace detail {

class AesDecryptImpl128 : public crypto::detail::IAesDecryptor128 {
public:
    AesDecryptImpl128();
    AesDecryptImpl128(const void* pKey, size_t keySize);
    virtual ~AesDecryptImpl128();

    virtual void Initialize(const void* pKey, size_t keySize) override;
    virtual void Finalize() override;

    virtual void DecryptBlock(void* pOut, const void* pIn) override;

private:
    void ExpandKeyImpl();

private:
    uint8_t m_RoundKeys[11][16];
    uint32_t m_InvRoundKeys[11][4];
};

} // namespace detail
} // namespace crypto
