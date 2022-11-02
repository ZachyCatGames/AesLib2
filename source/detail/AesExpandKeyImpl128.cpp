#include <cstdint>
#include <AesLib/detail/AesLookupTables128.h>

namespace crypto {
namespace detail {

void AesExpandKeyImpl128(void* pKeyData) {
    uint32_t* pKeys = static_cast<uint32_t*>(pKeyData);
    uint32_t tmp;

    for(uint8_t round = 1; round < 11; round++) {
        uint32_t* curKey = pKeys + (round * 4);
        uint32_t* preKey = pKeys + (round - 1) * 4;
        tmp = preKey[3];

        /* Subsitute bytes */
        tmp = (sbox[(tmp >> 0x00) & 0xFF] << 0x00) |
              (sbox[(tmp >> 0x08) & 0xFF] << 0x08) |
              (sbox[(tmp >> 0x10) & 0xFF] << 0x10) |
              (sbox[(tmp >> 0x18) & 0xFF] << 0x18);


        /* Rotate bytes. */
        tmp = (tmp >> 0x8) | ((tmp & 0xFF) << 0x18);

        /* Handle first word. */
        curKey[0] = preKey[0] ^ tmp ^ rcon[round];

        /* XOR each word with the previous word from the previous key. */
        curKey[1] = curKey[0] ^ preKey[1];
        curKey[2] = curKey[1] ^ preKey[2];
        curKey[3] = curKey[2] ^ preKey[3];
    }
}

} // namespace detail
} // namespace crypto
