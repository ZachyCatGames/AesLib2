#pragma once
#include <cstddef>
#include <cstdint>
#include <AesLib/detail/IAesEncryptor128.h>

namespace crypto {
namespace detail {
namespace arch {
namespace aarch64 {

class AesEncryptImpl128 : public crypto::detail::IAesEncryptor128 {
public:
    AesEncryptImpl128();
    AesEncryptImpl128(const void* pKey, size_t keySize);
    virtual ~AesEncryptImpl128();

    virtual void Initialize(const void* pKey, size_t keySize) override;
    virtual void Finalize() override;

    virtual void EncryptBlock(void* pOut, const void* pIn) override;

private:
    uint32_t m_RoundKeys[11 * 4 + 2]; // Extra 2 for alignment.
};

} // namespace aarch64
} // namespace arch
} // namespace detail
} // namespace crypto
