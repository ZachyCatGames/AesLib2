#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor.h>

namespace crypto {
namespace detail {

template<int KeyLength>
class AesDecryptImpl : public IAesDecryptor {
public:
    static constexpr int KeySize = KeyLength / 8;
public:
    AesDecryptImpl();
    AesDecryptImpl(const void* pKey, size_t keySize);
    virtual ~AesDecryptImpl();

    virtual void Initialize(const void* pKey, size_t keySize) override;
    virtual void Finalize() override;

    virtual void DecryptBlock(void* pOut, const void* pIn) override;
private:
    static constexpr int m_KeyWordCount = KeyLength == 128 ? 44 : KeyLength == 192 ? 52 : 60;
    static constexpr int m_Rounds = KeyLength == 128 ? 11 : KeyLength == 192 ? 13 : 15;
    uint32_t m_RoundKeys[m_Rounds * 4];
}; // class AesDecryptImpl

} // namespace detail
} // namespace crypto
