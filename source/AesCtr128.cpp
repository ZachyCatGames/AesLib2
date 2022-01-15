#include <AesCtr128.h>

namespace crypto {
    void AesCtr128::IncreaseStrCtr(size_t ammount) {
        for(size_t j = 0; j < ammount; j++) {
            for(uint8_t i = Aes128BlockLength - 1; i >= 0; i--) {
                m_AesStoredCounter[i]++;
                if(m_AesStoredCounter[i])
                    break;
            }
        }
    }

    void AesCtr128::DecreaseStrCtr(size_t ammount) {
        for(size_t j = 0; j < ammount; j++) {
            for(uint8_t i = Aes128BlockLength - 1; i >= 0; i--) {
                m_AesStoredCounter[i]--;
                if(m_AesStoredCounter[i] != 0xFF)
                    break;
            }
        }
    }

    void AesCtr128::IncrementStoredCounter(int64_t ammount) {
        if(ammount < 0) {
            DecreaseStrCtr(ammount * -1);
        } else {
            IncreaseStrCtr(ammount);
        }
    }

    Aes128Result AesCtr128::CryptBlock(void* output, const void* input) {
        uint8_t ctr[Aes128BlockLength];
        uint8_t tmp[Aes128BlockLength];

        /* Copy iv to ctr */
        std::memcpy(ctr, m_AesCounter, Aes128BlockLength);

        /* Encrypt CTR with key */
        m_EcbEncrypter.EncryptBlock(tmp, ctr);

        /* XOR Data with encrypted CTR */
        for(uint8_t i = 0; i < 4; i++) {
            reinterpret_cast<uint32_t*>(output)[i] = reinterpret_cast<const uint32_t*>(input)[i] ^ reinterpret_cast<uint32_t*>(tmp)[i];
        }

        /* Return */
        return Result_Success;
    }

    Aes128Result AesCtr128::CryptData(void* output, const void* input, const size_t size, const bool saveCtr, const bool useStoredCtr) {
        uint8_t ctr[Aes128BlockLength];
        uint8_t tmp[Aes128BlockLength];
        int64_t lengthLeft = size;
        int64_t pos = 0;

        /* Copy iv to ctr */
        if(useStoredCtr) {
            std::memcpy(ctr, m_AesStoredCounter, Aes128BlockLength);
        } else {
            std::memcpy(ctr, m_AesCounter, Aes128BlockLength);
        }

        while(lengthLeft > 0) {
            /* Encrypt CTR with key */
            m_EcbEncrypter.EncryptBlock(tmp, ctr);

            /* XOR Data with encrypted CTR */
            for(uint8_t i = 0; i < (lengthLeft > Aes128BlockLength ? Aes128BlockLength : lengthLeft); i++) {
                static_cast<uint8_t*>(output)[i + pos] = static_cast<const uint8_t*>(input)[i + pos] ^ tmp[i];
            }

            /* Increment CTR */
            for(uint8_t i = Aes128BlockLength - 1; i >= 0; i--) {
                ctr[i]++;
                if(ctr[i])
                    break;
            }

            /* Increment Position */
            lengthLeft -= Aes128BlockLength;
            pos        += Aes128BlockLength;
        }

        if(saveCtr) {
            std::memcpy(m_AesStoredCounter, ctr, Aes128BlockLength);
        }

        /* Return */
        return Result_Success;
    }
}
