#pragma once
#include <cstddef>
#include <cstdint>
#include <wmmintrin.h>
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor128.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

class AesEncryptImpl128 : public crypto::detail::IAesEncryptor128 {
public:
    AesEncryptImpl128();
    AesEncryptImpl128(const void* pKey, size_t keySize);
    virtual ~AesEncryptImpl128();

    virtual void Initialize(const void* pKey, size_t keySize) override;
    virtual void Finalize() override;

    virtual void EncryptBlock(void* pOut, const void* pIn) override;

private:
    void ExpandKeyImpl(const void* pKey);

private:
    uint8_t m_RoundKeyStorage[20][16];
};

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
