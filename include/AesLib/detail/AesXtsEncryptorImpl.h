#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/AesXtsNTweakHandler.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <cstdint>
#include <cstddef>

namespace crypto {
namespace detail {

template<typename TweakHandler>
class AesXtsEncryptorImpl {
public:
    AesXtsEncryptorImpl(UniqueEncryptor&& pEnc1, UniqueEncryptor&& pEnc2);
    AesXtsEncryptorImpl(UniqueEncryptor&& pEnc1, UniqueEncryptor&& pEnc2, std::size_t sectSize);
    ~AesXtsEncryptorImpl();

    void Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    void Finalize();

    AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr);
private:
    UniqueEncryptor m_pEncryptor;
    TweakHandler m_TweakHandler;
    size_t m_SectorSize;
}; // class AesXtsEncryptorImpl

} // namespace detail
} // namespace crypto
