#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/AesXtsNTweakHandler.h>
#include <AesLib/detail/IAesDecryptor.h>
#include <cstdint>
#include <cstddef>

namespace crypto {
namespace detail {

template<typename TweakHandler>
class AesXtsDecryptorImpl {
public:
    AesXtsDecryptorImpl(UniqueDecryptor&& pEnc1, UniqueEncryptor&& pEnc2);
    AesXtsDecryptorImpl(UniqueDecryptor&& pEnc1, UniqueEncryptor&& pEnc2, std::size_t sectSize);
    ~AesXtsDecryptorImpl();

    void Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    void Finalize();

    AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr);
private:
    UniqueDecryptor m_pDecryptor;
    TweakHandler m_TweakHandler;
    size_t m_SectorSize;
}; // class AesXtsDecryptorImpl

} // namespace detail
} // namespace crypto
