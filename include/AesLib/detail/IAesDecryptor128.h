#pragma once
#include <cstddef>

namespace crypto {
namespace detail {

class IAesDecryptor128 {
public:
    virtual ~IAesDecryptor128() = default;

    virtual void Initialize(const void* pKey, size_t keySize) = 0;
    virtual void Finalize() = 0;

    virtual void DecryptBlock(void* pOut, const void* pIn) = 0;
};

} // namespace detail
} // namespace crypto
