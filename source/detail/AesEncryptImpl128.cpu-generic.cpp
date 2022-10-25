#include <AesLib/detail/AesEncryptImpl128.cpu-generic.h>
#include <AesLib/AesLookupTables.h>

namespace crypto {
namespace detail {

AesEncryptImpl128::AesEncryptImpl128() = default;

AesEncryptImpl128::AesEncryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesEncryptImpl128::~AesEncryptImpl128() = default;

void AesEncryptImpl128::Initialize(const void* pKey, size_t keySize) {
    std::memcpy(m_RoundKeys[0], pKey, 0x10);
    this->ExpandKeyImpl();
}

void AesEncryptImpl128::Finalize() {
    /* ... */
}

void AesEncryptImpl128::ExpandKeyImpl() {
    uint8_t tmp[4];

    for(uint8_t round = 0; round < 10; round++) {
        uint8_t* nextKey = m_RoundKeys[round + 1];

        /* Copy current key to next key */
        std::memcpy(nextKey, m_RoundKeys[round], 0x10);

            /* Subsitute bytes */
        tmp[0] = sbox[nextKey[13]];
        tmp[1] = sbox[nextKey[14]];
        tmp[2] = sbox[nextKey[15]];
        tmp[3] = sbox[nextKey[12]];

        /* XOR key with subsituted bytes */
         nextKey[0] = nextKey[0] ^ (tmp[0] ^ rcon[round+1]);
        for(uint8_t i = 1; i < 4; i++) {
            nextKey[i] ^= tmp[i];
        }

        /* XOR bytes with previous byte */
        for(uint8_t roundIterations = 1; roundIterations < 4; roundIterations++) {
            reinterpret_cast<uint32_t*>(nextKey)[roundIterations] ^= reinterpret_cast<uint32_t*>(nextKey)[roundIterations-1];
        }
    }
}

void AesEncryptImpl128::EncryptBlock(void* pOut, const void* pIn) {
    constexpr const uint8_t roundCount = 9;
    uint8_t tmp[16];
    auto output = static_cast<uint8_t*>(pOut);
    auto input = static_cast<const uint8_t*>(pIn);

    /* Add roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        reinterpret_cast<uint32_t*>(output)[i] = reinterpret_cast<const uint32_t*>(input)[i] ^ reinterpret_cast<uint32_t*>(m_RoundKeys[0])[i];
    }

    for(uint8_t round = 1; round <= roundCount; round++) {
        /* Subsitute Bytes, Shift Rows, and Mix Columns */
        tmp[0]  = sbox_mul2[output[0]]  ^ sbox_mul3[output[5]]  ^ sbox[output[10]]      ^ sbox[output[15]];
        tmp[1]  = sbox[output[0]]       ^ sbox_mul2[output[5]]  ^ sbox_mul3[output[10]] ^ sbox[output[15]];
        tmp[2]  = sbox[output[0]]       ^ sbox[output[5]]       ^ sbox_mul2[output[10]] ^ sbox_mul3[output[15]];
        tmp[3]  = sbox_mul3[output[0]]  ^ sbox[output[5]]       ^ sbox[output[10]]      ^ sbox_mul2[output[15]];

        tmp[4]  = sbox_mul2[output[4]]  ^ sbox_mul3[output[9]]  ^ sbox[output[14]]      ^ sbox[output[3]];
        tmp[5]  = sbox[output[4]]       ^ sbox_mul2[output[9]]  ^ sbox_mul3[output[14]] ^ sbox[output[3]];
        tmp[6]  = sbox[output[4]]       ^ sbox[output[9]]       ^ sbox_mul2[output[14]] ^ sbox_mul3[output[3]];
        tmp[7]  = sbox_mul3[output[4]]  ^ sbox[output[9]]       ^ sbox[output[14]]      ^ sbox_mul2[output[3]];

        tmp[8]  = sbox_mul2[output[8]]  ^ sbox_mul3[output[13]] ^ sbox[output[2]]       ^ sbox[output[7]];
        tmp[9]  = sbox[output[8]]       ^ sbox_mul2[output[13]] ^ sbox_mul3[output[2]]  ^ sbox[output[7]];
        tmp[10] = sbox[output[8]]       ^ sbox[output[13]]      ^ sbox_mul2[output[2]]  ^ sbox_mul3[output[7]];
        tmp[11] = sbox_mul3[output[8]]  ^ sbox[output[13]]      ^ sbox[output[2]]       ^ sbox_mul2[output[7]]; 

        tmp[12] = sbox_mul2[output[12]] ^ sbox_mul3[output[1]]  ^ sbox[output[6]]       ^ sbox[output[11]];
        tmp[13] = sbox[output[12]]      ^ sbox_mul2[output[1]]  ^ sbox_mul3[output[6]]  ^ sbox[output[11]];
        tmp[14] = sbox[output[12]]      ^ sbox[output[1]]       ^ sbox_mul2[output[6]]  ^ sbox_mul3[output[11]];
        tmp[15] = sbox_mul3[output[12]] ^ sbox[output[1]]       ^ sbox[output[6]]       ^ sbox_mul2[output[11]];
        std::memcpy(output, tmp, 0x10);

        /* Add roundkey */
        for(uint8_t i = 0; i < 4; i++) {
            reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_RoundKeys[round])[i];
        }
    }

    /* Shift Rows Right and Subsitute */
    uint8_t value1 = sbox[output[5]];
    uint8_t value2 = sbox[output[10]];
    uint8_t value6 = sbox[output[14]];
    uint8_t value3 = sbox[output[15]];

    output[0] = sbox[output[0]];
    output[4] = sbox[output[4]];
    output[8] = sbox[output[8]];
    output[12] = sbox[output[12]];

    output[5] = sbox[output[9]];
    output[9] = sbox[output[13]];
    output[13] = sbox[output[1]];
    output[1] = value1;

    output[14] = sbox[output[6]];
    output[10] = sbox[output[2]];
    output[6] = value6;
    output[2] = value2;

    output[15] = sbox[output[11]];
    output[11] = sbox[output[7]];
    output[7] = sbox[output[3]];
    output[3] = value3;

    /* Add roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_RoundKeys[10])[i];
    }
}

} // namespace detail
} // namespace crypto
