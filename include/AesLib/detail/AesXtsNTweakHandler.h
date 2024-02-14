#pragma once
#include <AesLib/detail/IAesEncryptor.h>
#include <memory>

namespace crypto {
namespace detail {

class AesXtsNTweakHandler {
public:
    AesXtsNTweakHandler(UniqueEncryptor&& pEnc);
    ~AesXtsNTweakHandler();

    void Initialize(const void* pKey, size_t keySize);

    void SetupTweak(void* pOut, size_t curSector, size_t sectAddr);
private:
    UniqueEncryptor m_pEncryptor;
}; // class AesXtsNTweakHandler

} // namespace detail
} // namespace crypto
