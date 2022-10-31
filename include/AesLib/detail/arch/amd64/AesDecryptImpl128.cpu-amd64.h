#pragma once
#include <cstddef>
#include <cstdint>
#include <wmmintrin.h>
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor128.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

class AesDecryptImpl128 : public crypto::detail::IAesDecryptor128 {
public:
    AesDecryptImpl128();
    AesDecryptImpl128(const void* pKey, size_t keySize);
    virtual ~AesDecryptImpl128();

    virtual void Initialize(const void* pKey, size_t keySize) override;
    virtual void Finalize() override;

    virtual void DecryptBlock(void* pOut, const void* pIn) override;

private:
    void ExpandKeyImpl(const void* pKey);

private:
    uint8_t m_InvRoundKeyStorage[13][16];
};

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
