#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/AesXtsNTweakHandler.h>
#include <AesLib/detail/IAesDecryptor.h>
#include <cstdint>
#include <cstddef>

namespace crypto {

template<int KeyLength, typename TweakHandler>
class AesXtsDecryptor {
public:
    static constexpr int KeySize = KeyLength / 8;

public:
    AesXtsDecryptor();
    AesXtsDecryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    ~AesXtsDecryptor();

    void Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    void Finalize();

    AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr);

private:
    std::unique_ptr<detail::IAesDecryptor<KeyLength>> m_pDecryptor;
    TweakHandler m_TweakHandler;
    size_t m_SectorSize;
};

using AesXtsDecryptor128 = AesXtsDecryptor<128, detail::AesXtsTweakHandler<128>>;
using AesXtsDecryptor192 = AesXtsDecryptor<192, detail::AesXtsTweakHandler<192>>;
using AesXtsDecryptor256 = AesXtsDecryptor<256, detail::AesXtsTweakHandler<256>>;

using AesXtsNDecryptor128 = AesXtsDecryptor<128, detail::AesXtsNTweakHandler<128>>;
using AesXtsNDecryptor192 = AesXtsDecryptor<192, detail::AesXtsNTweakHandler<192>>;
using AesXtsNDecryptor256 = AesXtsDecryptor<256, detail::AesXtsNTweakHandler<256>>;

} // namespace crypto
