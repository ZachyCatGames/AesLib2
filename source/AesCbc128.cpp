#include <AesCbc128.h>

namespace crypto {
    Aes128Result AesCbc128::EncryptData(void* output, const void* input, const size_t size, const bool saveIv, const bool useStoredIv) {
        uint8_t tmp[Aes128BlockLength];
        uint8_t iv_buf[Aes128BlockLength];
        size_t pos = 0;

        /* Assert that data is aligned to 0x10 bytes */
        if(size % Aes128BlockLength != 0) {
            printf("Error: Size must be aligned to 0x10 bytes");
            return Result_DataNotAligned128;
        }

        /* Copy iv to iv_buf */
        if(useStoredIv) {
            std::memcpy(iv_buf, m_AesStoredIv, Aes128BlockLength);
        } else {
            std::memcpy(iv_buf, m_AesIv, Aes128BlockLength);
        }

        /* Loop until all data is encrypted */
        for(size_t i = 0; i < size; i += Aes128BlockLength) {
            /* Copy input at current position */
            std::memcpy(tmp, static_cast<const uint8_t*>(input) + pos, Aes128BlockLength);

            /* XOR Input with IV */
            for(uint8_t i = 0; i < 4; i++) {
                reinterpret_cast<uint32_t*>(tmp)[i] ^= reinterpret_cast<uint32_t*>(iv_buf)[i];
            }

            /* Encrypt data with key */
            m_EcbEncrypter.EncryptBlock(static_cast<uint8_t*>(output) + pos, tmp);

            /* Copy encrypted data to iv_buf */
            std::memcpy(iv_buf, static_cast<uint8_t*>(output) + pos, Aes128BlockLength);

            /* Increment Position */
            pos += Aes128BlockLength;
        }

        /* Save IV if requested */
        if(saveIv) {
            std::memcpy(m_AesStoredIv, iv_buf, Aes128BlockLength);
        }

        /* Return */
        return Result_Success;
    }

    Aes128Result AesCbc128::DecryptData(void* output, const void* input, const size_t size, const bool saveIv, const bool useStoredIv) {
        uint8_t tmp[Aes128BlockLength];
        uint8_t iv_buf[Aes128BlockLength];
        uint8_t nextIv[Aes128BlockLength];
        size_t pos = 0;

        /* Assert that data is aligned to 0x10 bytes */
        if(size % Aes128BlockLength != 0) {
            printf("Error: Size must be aligned to 0x10 bytes");
            return Result_DataNotAligned128;
        }

        /* Copy iv to iv_buf */
        if(useStoredIv) {
            std::memcpy(iv_buf, m_AesStoredIv, Aes128BlockLength);
        } else {
            std::memcpy(iv_buf, m_AesIv, Aes128BlockLength);
        }

        /* Loop until all data is decrypted */
        for(size_t i = 0; i < size; i += Aes128BlockLength) {
            /* Copy encrypted data to next iv */
            std::memcpy(nextIv, static_cast<const uint8_t*>(input) + pos, Aes128BlockLength);

            /* Decrypt data with key */
            m_EcbEncrypter.DecryptBlock(tmp, static_cast<const uint8_t*>(input) + pos);

            /* XOR data with iv */
            for(uint8_t i = 0; i < Aes128BlockLength; i++) {
                (static_cast<uint8_t*>(output) + pos)[i] = tmp[i] ^ iv_buf[i];
            }

            /* Copy next iv to iv */
            std::memcpy(iv_buf, nextIv, Aes128BlockLength);

            /* Increment Position */
            pos += Aes128BlockLength;
        }

        /* Save IV if requested */
        if(saveIv) {
            std::memcpy(m_AesStoredIv, iv_buf, Aes128BlockLength);
        }

        /* Return */
        return Result_Success;
    }
}
