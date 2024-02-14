#pragma once
#include <cstddef>
#include <memory>

namespace crypto {
namespace detail {

class IAesEncryptor {
public:
    virtual ~IAesEncryptor() = default;

    virtual void Initialize(const void* pKey, size_t keySize) = 0;
    virtual void Finalize() = 0;

    virtual void EncryptBlock(void* pOut, const void* pIn) = 0;
};

using UniqueEncryptor = std::unique_ptr<IAesEncryptor>;

} // namespace detail
} // namespace crypto
