#include <AesLib/detail/AesDecryptImpl128.cpu-generic.h>
#include <AesLib/AesLookupTables.h>

namespace crypto {
namespace detail {

AesDecryptImpl128::AesDecryptImpl128() = default;

AesDecryptImpl128::AesDecryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesDecryptImpl128::~AesDecryptImpl128() = default;

void AesDecryptImpl128::Initialize(const void* pKey, size_t keySize) {
    std::memcpy(m_RoundKeys[0], pKey, 0x10);
    this->ExpandKeyImpl();
}

void AesDecryptImpl128::Finalize() {
    /* ... */
}

void AesDecryptImpl128::ExpandKeyImpl() {
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

void AesDecryptImpl128::DecryptBlock(void* pOut, const void* pIn) {
    constexpr const uint8_t roundCount = 9;
    uint8_t tmp[16] = {0};
    auto output = static_cast<uint8_t*>(pOut);
    auto input = static_cast<const uint8_t*>(pIn);

    /* Subtract Last Roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        reinterpret_cast<uint32_t*>(output)[i] = reinterpret_cast<const uint32_t*>(input)[i] ^ reinterpret_cast<uint32_t*>(m_RoundKeys[10])[i];
    }

    /* Shift Rows Left and Subsitute */
    uint8_t value1 = inv_s[output[13]];
    uint8_t value2 = inv_s[output[10]];
    uint8_t value6 = inv_s[output[14]];
    uint8_t value3 = inv_s[output[7]];

    output[0] = inv_s[output[0]];
    output[4] = inv_s[output[4]];
    output[8] = inv_s[output[8]];
    output[12] = inv_s[output[12]];

    output[13] = inv_s[output[9]];
    output[9] = inv_s[output[5]];
    output[5] = inv_s[output[1]];
    output[1] = value1;

    output[10] = inv_s[output[2]];
    output[14] = inv_s[output[6]];
    output[2] = value2;
    output[6] = value6;

    output[7] = inv_s[output[11]];
    output[11] = inv_s[output[15]];
    output[15] = inv_s[output[3]];
    output[3] = value3;

    for(uint8_t round = roundCount; round > 0; round--) {
        /* Subtract Roundkey */
        for(uint8_t i = 0; i < 4; i++) {
            reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_RoundKeys[round])[i];
        }

        /* Unmix Columns, Shift Rows, and Inverse Subsitute Bytes */
        tmp[0]  = inv_s[mul14[output[0]] ^ mul11[output[1]] ^ mul13[output[2]] ^ mul9[output[3]]];
        tmp[5]  = inv_s[mul9[output[0]]  ^ mul14[output[1]] ^ mul11[output[2]] ^ mul13[output[3]]];
        tmp[10] = inv_s[mul13[output[0]] ^ mul9[output[1]]  ^ mul14[output[2]] ^ mul11[output[3]]];
        tmp[15] = inv_s[mul11[output[0]] ^ mul13[output[1]] ^ mul9[output[2]]  ^ mul14[output[3]]];

        tmp[4]  = inv_s[mul14[output[4]] ^ mul11[output[5]] ^ mul13[output[6]] ^ mul9[output[7]]];
        tmp[9]  = inv_s[mul9[output[4]]  ^ mul14[output[5]] ^ mul11[output[6]] ^ mul13[output[7]]];
        tmp[14] = inv_s[mul13[output[4]] ^ mul9[output[5]]  ^ mul14[output[6]] ^ mul11[output[7]]];
        tmp[3]  = inv_s[mul11[output[4]] ^ mul13[output[5]] ^ mul9[output[6]]  ^ mul14[output[7]]];

        tmp[8]  = inv_s[mul14[output[8]]  ^ mul11[output[9]] ^ mul13[output[10]] ^ mul9[output[11]]];
        tmp[13] = inv_s[mul9[output[8]]   ^ mul14[output[9]] ^ mul11[output[10]] ^ mul13[output[11]]];
        tmp[2]  = inv_s[mul13[output[8]]  ^ mul9[output[9]]  ^ mul14[output[10]] ^ mul11[output[11]]];
        tmp[7]  = inv_s[mul11[output[8]]  ^ mul13[output[9]] ^ mul9[output[10]]  ^ mul14[output[11]]]; 

        tmp[12] = inv_s[mul14[output[12]] ^ mul11[output[13]] ^ mul13[output[14]] ^ mul9[output[15]]];
        tmp[1]  = inv_s[mul9[output[12]]  ^ mul14[output[13]] ^ mul11[output[14]] ^ mul13[output[15]]];
        tmp[6]  = inv_s[mul13[output[12]] ^ mul9[output[13]]  ^ mul14[output[14]] ^ mul11[output[15]]];
        tmp[11] = inv_s[mul11[output[12]] ^ mul13[output[13]] ^ mul9[output[14]]  ^ mul14[output[15]]]; 

        std::memcpy(output, tmp, 0x10);
    }

    /* Substract First Roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_RoundKeys[0])[i];
    }
}

} // namespace detail
} // namespace crypto
