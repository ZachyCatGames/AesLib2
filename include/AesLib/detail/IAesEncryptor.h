#pragma once
#include <cstddef>

namespace crypto {
namespace detail {

template<int KeyLength>
class IAesEncryptor {
public:
    virtual ~IAesEncryptor() = default;

    virtual void Initialize(const void* pKey, size_t keySize) = 0;
    virtual void Finalize() = 0;

    virtual void EncryptBlock(void* pOut, const void* pIn) = 0;
};

} // namespace detail
} // namespace crypto
