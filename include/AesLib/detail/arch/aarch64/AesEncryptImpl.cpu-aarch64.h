#pragma once
#include <cstddef>
#include <cstdint>
#include <AesLib/detail/IAesEncryptor.h>

namespace crypto {
namespace detail {
namespace arch {
namespace aarch64 {

template<int KeyLength>
class AesEncryptImpl : public crypto::detail::IAesEncryptor<KeyLength> {
public:
    AesEncryptImpl() = default;
    AesEncryptImpl(const void* pKey, size_t keySize) { this->Initialize(pKey, keySize); }
    virtual ~AesEncryptImpl() = default;

    virtual void Initialize(const void* pKey, size_t keySize) override;
    virtual void Finalize() override {}

    virtual void EncryptBlock(void* pOut, const void* pIn) override;

private:
    uint32_t m_RoundKeys[11 * 4 + 2]; // Extra 2 for alignment.
};

} // namespace aarch64
} // namespace arch
} // namespace detail
} // namespace crypto
