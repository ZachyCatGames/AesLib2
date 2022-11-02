#include <AesLib/detail/AesExpandKeyImpl256.h>
#include <AesLib/detail/AesLookupTables128.h>
#include <AesLib/detail/AesByteSwap.h>
#include <cstdio>

namespace crypto {
namespace detail {

void AesExpandKeyImpl256(void* pKeyData) {
    uint32_t* pKeys = static_cast<uint32_t*>(pKeyData);
    uint32_t tmp;

    for(int i = 8; i < 60; ++i) {
        tmp = pKeys[i - 1];

        /* Check if we need to rotate. */
        if(i % 8 == 0) {
            tmp = (pKeys[i - 1] >> 0x8) | ((pKeys[i - 1] & 0xFF) << 0x18);

            tmp = ((sbox[(tmp >> 0x00) & 0xFF] << 0x00) |
                   (sbox[(tmp >> 0x08) & 0xFF] << 0x08) |
                   (sbox[(tmp >> 0x10) & 0xFF] << 0x10) |
                   (sbox[(tmp >> 0x18) & 0xFF] << 0x18)) ^ rcon[i / 8];
        }
        else if(i % 4 == 0) {
            tmp = (sbox[(tmp >> 0x00) & 0xFF] << 0x00) |
                  (sbox[(tmp >> 0x08) & 0xFF] << 0x08) |
                  (sbox[(tmp >> 0x10) & 0xFF] << 0x10) |
                  (sbox[(tmp >> 0x18) & 0xFF] << 0x18);
        }

        pKeys[i] = pKeys[i - 8] ^ tmp;
    }
}

} // namespace detail
} // namespace crypto
