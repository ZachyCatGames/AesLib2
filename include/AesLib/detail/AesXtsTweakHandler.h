#pragma once
#include <AesLib/detail/IAesEncryptor128.h>
#include <memory>

namespace crypto {
namespace detail {

class AesXtsTweakHandler {
public:
    AesXtsTweakHandler();
    AesXtsTweakHandler(const void* pKey, size_t keySize);
    ~AesXtsTweakHandler();

    void Initialize(const void* pKey, size_t keySize);

    void SetupTweak(void* pOut, size_t curSector, size_t sectAddr);

private:
    std::unique_ptr<crypto::detail::IAesEncryptor128> m_pEncryptor;
};

} // namespace detail
} // namespace crypto
