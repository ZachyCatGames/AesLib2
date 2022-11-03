#pragma once
#include <cstddef>
#include <cstdint>
#include <wmmintrin.h>
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

template<int KeyLength>
class AesEncryptImpl : public crypto::detail::IAesEncryptor<KeyLength> {
public:
    static constexpr int KeySize = KeyLength / 8;

public:
    AesEncryptImpl();
    AesEncryptImpl(const void* pKey, size_t keySize);
    virtual ~AesEncryptImpl();

    virtual void Initialize(const void* pKey, size_t keySize) override;
    virtual void Finalize() override;

    virtual void EncryptBlock(void* pOut, const void* pIn) override;

private:
    void ExpandKeyImpl(const void* pKey);

private:
    static constexpr int m_KeyWordCount = KeyLength == 128 ? 44 : KeyLength == 192 ? 52 : 60;
    static constexpr int m_Rounds = KeyLength == 128 ? 11 : KeyLength == 192 ? 13 : 15;
    uint32_t m_RoundKeyStorage[m_Rounds][4];
};

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
