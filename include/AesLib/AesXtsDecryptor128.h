#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/IAesDecryptor128.h>
#include <cstdint>
#include <cstddef>

namespace crypto {

class AesXtsDecryptor128 {
public:
    AesXtsDecryptor128();
    AesXtsDecryptor128(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    ~AesXtsDecryptor128();

    void Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    void Finalize();

    crypto::AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr);

private:
    std::unique_ptr<crypto::detail::IAesDecryptor128> m_pDecryptor;
    crypto::detail::AesXtsTweakHandler m_TweakHandler;
    size_t m_SectorSize;
};

} // namespace crypto
