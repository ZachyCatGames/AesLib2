#pragma once
#include <cstddef>
#include <cstdint>
#include <AesLib/detail/IAesDecryptor128.h>

namespace crypto {
namespace detail {
namespace arch {
namespace aarch64 {

class AesDecryptImpl128 : public crypto::detail::IAesDecryptor128 {
public:
    AesDecryptImpl128();
    AesDecryptImpl128(const void* pKey, size_t keySize);
    virtual ~AesDecryptImpl128();

    virtual void Initialize(const void* pKey, size_t keySize) override;
    virtual void Finalize() override;

    virtual void DecryptBlock(void* pOut, const void* pIn) override;

private:
    uint32_t m_RoundKeys[11 * 4][4];
};

} // namespace aarch64
} // namespace arch
} // namespace detail
} // namespace crypto
