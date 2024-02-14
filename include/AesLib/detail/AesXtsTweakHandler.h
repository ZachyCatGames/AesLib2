#pragma once
#include <AesLib/detail/IAesEncryptor.h>
#include <memory>

namespace crypto {
namespace detail {

class AesXtsTweakHandler {
public:
    AesXtsTweakHandler(UniqueEncryptor&& pEnc);
    ~AesXtsTweakHandler();

    void Initialize(const void* pKey, size_t keySize);

    void SetupTweak(void* pOut, size_t curSector, size_t sectAddr);
private:
    UniqueEncryptor m_pEncryptor;
}; // class AesXtsTweakHandler

} // namespace detail
} // namespace crypto
