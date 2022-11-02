#include <AesLib/detail/AesExpandKeyImpl.h>
#include <AesLib/detail/AesLookupTables128.h>
#include <cstdint>

namespace crypto {
namespace detail {

template<int KeyLength>
void AesExpandKeyImpl(void* pKeyData) {
    constexpr int wordCount = KeyLength == 128 ? 44 : KeyLength == 192 ? 52 : 60;
    constexpr int keyWordSize = KeyLength / 32;
    uint32_t* pKeys = static_cast<uint32_t*>(pKeyData);
    uint32_t tmp;

    for(int i = keyWordSize; i < wordCount; ++i) {
        tmp = pKeys[i - 1];

        /* Check if we need to rotate. */
        if(i % keyWordSize == 0) {
            tmp = (pKeys[i - 1] >> 0x8) | ((pKeys[i - 1] & 0xFF) << 0x18);

            tmp = ((sbox[(tmp >> 0x00) & 0xFF] << 0x00) |
                   (sbox[(tmp >> 0x08) & 0xFF] << 0x08) |
                   (sbox[(tmp >> 0x10) & 0xFF] << 0x10) |
                   (sbox[(tmp >> 0x18) & 0xFF] << 0x18)) ^ rcon[i / keyWordSize];
        }
        else if (i % 4 == 0) {
            if constexpr(KeyLength == 256) {
                tmp = (sbox[(tmp >> 0x00) & 0xFF] << 0x00) |
                      (sbox[(tmp >> 0x08) & 0xFF] << 0x08) |
                      (sbox[(tmp >> 0x10) & 0xFF] << 0x10) |
                      (sbox[(tmp >> 0x18) & 0xFF] << 0x18);
            }
        }

        pKeys[i] = pKeys[i - keyWordSize] ^ tmp;
    }
}

template void AesExpandKeyImpl<128>(void* pKeyData);
template void AesExpandKeyImpl<192>(void* pKeyData);
template void AesExpandKeyImpl<256>(void* pKeyData);

} // namespace detail
} // namespace crypto
