#pragma once
#include <AesLib/detail/IAesEncryptor.h>
#include <memory>

namespace crypto {
namespace detail {

template<int KeyLength>
class AesXtsNTweakHandler {
public:
    AesXtsNTweakHandler();
    AesXtsNTweakHandler(const void* pKey, size_t keySize);
    ~AesXtsNTweakHandler();

    void Initialize(const void* pKey, size_t keySize);

    void SetupTweak(void* pOut, size_t curSector, size_t sectAddr);

private:
    std::unique_ptr<crypto::detail::IAesEncryptor<KeyLength>> m_pEncryptor;
};

} // namespace detail
} // namespace crypto
