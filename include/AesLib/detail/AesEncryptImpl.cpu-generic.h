#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <cstdio>

namespace crypto {
namespace detail {

template<int KeyLength>
class AesEncryptImpl : public crypto::detail::IAesEncryptor<KeyLength> {
public:
    static constexpr int KeySize = KeyLength / 8;

public:
    AesEncryptImpl();
    AesEncryptImpl(const void* pKey, size_t keySize);
    virtual ~AesEncryptImpl();

    virtual void Initialize(const void* pKey, size_t keySize);
    virtual void Finalize();

    virtual void EncryptBlock(void* pOut, const void* pIn);

private:
    static constexpr int m_Rounds = KeyLength == 128 ? 11 : KeyLength == 192 ? 13 : 15;
    uint32_t m_RoundKeys[m_Rounds][4];
};

} // namespace detail
} // namespace crypto
