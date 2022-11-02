#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <cstdint>
#include <cstddef>

namespace crypto {

template<int KeyLength>
class AesXtsEncryptor {
public:
    static constexpr int KeySize = KeyLength / 8;

public:
    AesXtsEncryptor();
    AesXtsEncryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    ~AesXtsEncryptor();

    void Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    void Finalize();

    crypto::AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr);

private:
    std::unique_ptr<crypto::detail::IAesEncryptor<KeyLength>> m_pEncryptor;
    crypto::detail::AesXtsTweakHandler<KeyLength> m_TweakHandler;
    size_t m_SectorSize;
};

using AesXtsEncryptor128 = AesXtsEncryptor<128>;
using AesXtsEncryptor192 = AesXtsEncryptor<192>;
using AesXtsEncryptor256 = AesXtsEncryptor<256>;

} // namespace crypto
