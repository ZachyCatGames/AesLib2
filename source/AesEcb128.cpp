#include <AesEcb128.h>

namespace crypto {
    void AesEcb128::ExpandKeyGeneric() {
        uint8_t tmp[4];

        for(uint8_t round = 0; round < 10; round++) {
            uint8_t* nextKey = m_AesRoundKeys[round + 1];

            /* Copy current key to next key */
            std::memcpy(nextKey, m_AesRoundKeys[round], 0x10);

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

    void AesEcb128::EncryptBlockGeneric(uint8_t* output, const uint8_t* input) {
        constexpr const uint8_t roundCount = 9;
        uint8_t tmp[16];

        /* Add roundkey */
        for(uint8_t i = 0; i < 4; i++) {
            reinterpret_cast<uint32_t*>(output)[i] = reinterpret_cast<const uint32_t*>(input)[i] ^ reinterpret_cast<uint32_t*>(m_AesRoundKeys[0])[i];
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
                reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_AesRoundKeys[round])[i];
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
            reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_AesRoundKeys[10])[i];
        }
    }

    void AesEcb128::DecryptBlockGeneric(uint8_t* output, const uint8_t* input) {
        constexpr const uint8_t roundCount = 9;
        uint8_t tmp[16] = {0};

        /* Subtract Last Roundkey */
        for(uint8_t i = 0; i < 4; i++) {
            reinterpret_cast<uint32_t*>(output)[i] = reinterpret_cast<const uint32_t*>(input)[i] ^ reinterpret_cast<uint32_t*>(m_AesRoundKeys[10])[i];
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
                reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_AesRoundKeys[round])[i];
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
            reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_AesRoundKeys[0])[i];
        }
    }

    #if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
    __m128i aes_128_key_expansion(__m128i key, __m128i keygened){
        keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        return _mm_xor_si128(key, keygened);
    }

    void AesEcb128::ExpandKeyAmd64() { 
        m_Amd64RoundKeys[1]  = AES_128_key_exp(m_Amd64RoundKeys[0], 0x01);
        m_Amd64RoundKeys[2]  = AES_128_key_exp(m_Amd64RoundKeys[1], 0x02);
        m_Amd64RoundKeys[3]  = AES_128_key_exp(m_Amd64RoundKeys[2], 0x04);
        m_Amd64RoundKeys[4]  = AES_128_key_exp(m_Amd64RoundKeys[3], 0x08);
        m_Amd64RoundKeys[5]  = AES_128_key_exp(m_Amd64RoundKeys[4], 0x10);
        m_Amd64RoundKeys[6]  = AES_128_key_exp(m_Amd64RoundKeys[5], 0x20);
        m_Amd64RoundKeys[7]  = AES_128_key_exp(m_Amd64RoundKeys[6], 0x40);
        m_Amd64RoundKeys[8]  = AES_128_key_exp(m_Amd64RoundKeys[7], 0x80);
        m_Amd64RoundKeys[9]  = AES_128_key_exp(m_Amd64RoundKeys[8], 0x1B);
        m_Amd64RoundKeys[10] = AES_128_key_exp(m_Amd64RoundKeys[9], 0x36);

        /* Inverse Keys */
        for(uint8_t i = 0; i < 10; i++) {
            m_Amd64InvRoundKeys[i] = _mm_aesimc_si128(m_Amd64RoundKeys[i]);
        }
    }

    void AesEcb128::EncryptBlockAmd64(__m128i* output, const __m128i* input) {
        constexpr const uint8_t roundCount = 9;

        /* Add first roundkey */
        __m128i block = _mm_xor_si128(*input, m_Amd64RoundKeys[0]);

        /* Add roundkeys */
        for(uint8_t round = 1; round <= roundCount; round++) {
            block = _mm_aesenc_si128(block, m_Amd64RoundKeys[round]);
        }

        /* Add last roundkey */
        *output = _mm_aesenclast_si128(block, m_Amd64RoundKeys[10]);
    }

    void AesEcb128::DecryptBlockAmd64(__m128i* output, const __m128i* input) {
        constexpr const uint8_t roundCount = 9;

        /* Subtract first round key */\
        __m128i block = _mm_xor_si128(*input, m_Amd64RoundKeys[10]);

        /* Subtract round keys */
        for(uint8_t round = roundCount; round > 0; round--) {
            block = _mm_aesdec_si128(block, m_Amd64InvRoundKeys[round]);
        }

        /* Subtract last round key */
        *output = _mm_aesdeclast_si128(block, m_Amd64RoundKeys[0]);
    }
    #endif

    Aes128Result AesEcb128::EncryptBlock(void* output, const void* input) {
        /* Encrypt Block */
    #if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
        this->EncryptBlockAmd64(static_cast<__m128i*>(output), static_cast<const __m128i*>(input));
    #else
        this->EncryptBlockGeneric(static_cast<uint8_t*>(output), static_cast<const uint8_t*>(input));
    #endif

        /* Return */
        return Result_Success;
    }

    Aes128Result AesEcb128::DecryptBlock(void* output, const void* input) {
        /* Decrypt Block */
    #if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
        this->DecryptBlockAmd64(static_cast<__m128i*>(output), static_cast<const __m128i*>(input));
    #else
        this->DecryptBlockGeneric(static_cast<uint8_t*>(output), static_cast<const uint8_t*>(input));
    #endif
    
        /* Return */
        return Result_Success;
    }

    Aes128Result AesEcb128::EncryptData(void* output, const void* input, const size_t size) {
        /* Assert that data is aligned to 0x10 bytes */
        if(size % Aes128BlockLength != 0) {
            printf("Error: Size must be aligned to 0x10 bytes");
            return Result_DataNotAligned128;
        }

    #if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
        const size_t blockCount = size / Aes128BlockLength;
        for(size_t i = 0; i < blockCount; i++) {
            /* Decrypt Block */
            this->EncryptBlockAmd64(static_cast<__m128i*>(output) + i, static_cast<const __m128i*>(input) + i);
        }
    #else
        for(size_t i = 0; i < size; i += Aes128BlockLength) {
            /* Decrypt Block */
            this->EncryptBlockGeneric(static_cast<uint8_t*>(output) + i, static_cast<const uint8_t*>(input) + i);
        }
    #endif

        /* Return */
        return Result_Success;
    }

    Aes128Result AesEcb128::DecryptData(void* output, const void* input, const size_t size) {
        /* Assert that data is aligned to 0x10 bytes */
        if(size % Aes128BlockLength != 0) {
            printf("Error: Size must be aligned to 0x10 bytes");
            return Result_DataNotAligned128;
        }

    #if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
        const size_t blockCount = size / Aes128BlockLength;
        for(size_t i = 0; i < blockCount; i++) {
            /* Decrypt Block */
            this->DecryptBlockAmd64(static_cast<__m128i*>(output) + i, static_cast<const __m128i*>(input) + i);
        }
    #else
        for(size_t i = 0; i < size; i += Aes128BlockLength) {
            /* Decrypt Block */
            this->DecryptBlockGeneric(static_cast<uint8_t*>(output) + i, static_cast<const uint8_t*>(input) + i);
        }
    #endif

        /* Return */
        return Result_Success;
    }
}
