#pragma once
#include <AesLib/AesEcbEncryptor128.h>

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
    crypto::AesEcbEncryptor128 m_Encryptor;
};

} // namespace detail
} // namespace crypto
