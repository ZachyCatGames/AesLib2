#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesEncryptImpl128.h>
#include <AesLib/detail/AesXtsTweakHandler.h>
#include <cstdint>
#include <cstddef>

namespace crypto {

class AesXtsEncryptor128 {
public:
    AesXtsEncryptor128();
    AesXtsEncryptor128(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    ~AesXtsEncryptor128();

    void Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    void Finalize();

    crypto::AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr);

private:
    crypto::detail::AesEncryptImpl128 m_Encryptor;
    crypto::detail::AesXtsTweakHandler m_TweakHandler;
    size_t m_SectorSize;
};

} // namespace crypto
