#pragma once
#include <cstddef>

namespace crypto {
namespace detail {

template<int KeyLength>
class IAesDecryptor {
public:
    virtual ~IAesDecryptor() = default;

    virtual void Initialize(const void* pKey, size_t keySize) = 0;
    virtual void Finalize() = 0;

    virtual void DecryptBlock(void* pOut, const void* pIn) = 0;
};

} // namespace detail
} // namespace crypto
