#pragma once
#include <cstddef>
#include <cstdint>
#include <wmmintrin.h>
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

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
    void ExpandKeyImpl(const void* pKey);

private:
    static constexpr int m_KeyWordCount = KeyLength == 128 ? 44 : KeyLength == 192 ? 52 : 60;
    static constexpr int m_Rounds = KeyLength == 128 ? 11 : KeyLength == 192 ? 13 : 15;
    uint8_t m_RoundKeyStorage[m_Rounds][16];
};

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
