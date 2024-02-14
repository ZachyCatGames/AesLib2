#pragma once
#include <cstddef>
#include <memory>

namespace crypto {
namespace detail {

class IAesDecryptor {
public:
    virtual ~IAesDecryptor() = default;

    virtual void Initialize(const void* pKey, size_t keySize) = 0;
    virtual void Finalize() = 0;

    virtual void DecryptBlock(void* pOut, const void* pIn) = 0;
};

using UniqueDecryptor = std::unique_ptr<IAesDecryptor>;

} // namespace detail
} // namespace crypto
