#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/IAesDecryptor.h>
#include <cstdint>
#include <cstddef>

namespace crypto {

template<int KeyLength>
class AesXtsDecryptor {
public:
    static constexpr int KeySize = KeyLength / 8;

public:
    AesXtsDecryptor();
    AesXtsDecryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    ~AesXtsDecryptor();

    void Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    void Finalize();

    crypto::AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr);

private:
    std::unique_ptr<crypto::detail::IAesDecryptor<KeyLength>> m_pDecryptor;
    crypto::detail::AesXtsTweakHandler<KeyLength> m_TweakHandler;
    size_t m_SectorSize;
};

using AesXtsDecryptor128 = AesXtsDecryptor<128>;
using AesXtsDecryptor192 = AesXtsDecryptor<192>;
using AesXtsDecryptor256 = AesXtsDecryptor<256>;

} // namespace crypto
