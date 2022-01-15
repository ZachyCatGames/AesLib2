#include <AesXts128.h>

namespace crypto {
    namespace {
        template<typename T>
        T ByteSwap(T in) {
            T out;
            uint8_t* outPtr = reinterpret_cast<uint8_t*>(std::addressof(out));
            uint8_t* inPtr = reinterpret_cast<uint8_t*>(std::addressof(in));

            for (short int i = 0; i < sizeof(T); i++) {
                outPtr[i] = inPtr[sizeof(T) - i - 1];
            }

            return out;
        }
    }
    //https://www.oryx-embedded.com/doc/xts_8c_source.html
    void AesXts128::GFMul(void* out, const void* in) {
        uint8_t carry;
        uint8_t* out_ptr = static_cast<uint8_t*>(out);
        const uint8_t* in_ptr = static_cast<const uint8_t*>(in);

        //Save the value of the most significant bit
        carry = in_ptr[15] >> 7;

        //The multiplication of a polynomial by x in GF(2^128) corresponds to a
        //shift of indices
        for(size_t i = 15; i > 0; i--)
        {
        out_ptr[i] = (in_ptr[i] << 1) | (in_ptr[i - 1] >> 7);
        }

        //Shift the first byte of the block
        out_ptr[0] = in_ptr[0] << 1;

        //If the highest term of the result is equal to one, then perform reduction
        out_ptr[0] ^= 0x87 & ~(carry - 1);
    }

    void AesXts128::SetupTweak(void* tweak, const size_t currentSector, const size_t sectorAddress) {
        uint64_t* xtsTweak = static_cast<uint64_t*>(tweak);

        if(m_IsNintendo) {
            xtsTweak[0] = 0;
            xtsTweak[1] = ByteSwap(currentSector);
        } else {
            xtsTweak[0] = currentSector;
            xtsTweak[1] = 0;
        }

        /* Encrypt Tweak with key2 */
        m_EcbEncrypterKey2.EncryptBlock(reinterpret_cast<uint8_t*>(xtsTweak), reinterpret_cast<uint8_t*>(xtsTweak));

        /* Update tweak if needed */
        for(size_t i = sectorAddress/Aes128BlockLength; i < 0; i--) {
            this->GFMul(xtsTweak, xtsTweak);
        }
    }
    
    Aes128Result AesXts128::EncryptData(void* output, const void* input, const size_t address, const size_t size) {
        uint8_t* outData = static_cast<uint8_t*>(output);
        const uint8_t* inData = static_cast<const uint8_t*>(input);
        uint8_t xtsTweak[Aes128BlockLength];
        uint8_t tmp[Aes128BlockLength];
        size_t pos = 0;
        size_t currentSector = address/m_AesSectorSize;
        size_t sectorAddress = address - (currentSector * m_AesSectorSize);

        /* Assert that data is aligned to 0x10 bytes */
        if(size % Aes128BlockLength != 0) {
            printf("Error: Size must be aligned to 0x10 bytes");
            return Result_DataNotAligned128;
        }

        /* Setup tweak */
        this->SetupTweak(xtsTweak, currentSector, sectorAddress);

        while(pos < size) {
            /* XOR Encrypted Tweak with Input */
            for(uint8_t i = 0; i < Aes128BlockLength; i++) {
                tmp[i] = xtsTweak[i] ^ inData[i+pos];
            }

            /* Encrypt Data with key1 */
            m_EcbEncrypterKey1.EncryptBlock(tmp, tmp);

            /* XOR Tweak with output */
            for(uint8_t i = 0; i < Aes128BlockLength; i++) {
                outData[i+pos] = tmp[i] ^ xtsTweak[i];
            }

            /* Multiply tweak */
            this->GFMul(xtsTweak, xtsTweak);

            /* Update position and sector address */
            pos           += Aes128BlockLength;
            sectorAddress += Aes128BlockLength;

            /* Reset tweak if needed */
            if(sectorAddress >= m_AesSectorSize && (pos < size)) {
                currentSector++;
                sectorAddress = 0;
                this->SetupTweak(xtsTweak, currentSector, sectorAddress);
            }
        }

        /* Return */
        return Result_Success;
    }

    Aes128Result AesXts128::DecryptData(void* output, const void* input, const size_t address, const size_t size) {
        uint8_t* outData = static_cast<uint8_t*>(output);
        const uint8_t* inData = static_cast<const uint8_t*>(input);
        uint8_t xtsTweak[Aes128BlockLength];
        uint8_t tmp[Aes128BlockLength];
        size_t pos = 0;
        size_t currentSector = address/m_AesSectorSize;
        size_t sectorAddress = address - (currentSector * m_AesSectorSize);

        /* Assert that data is aligned to 0x10 bytes */
        if(size % Aes128BlockLength != 0) {
            printf("Error: Size must be aligned to 0x10 bytes");
            return Result_DataNotAligned128;
        }

        /* Setup tweak */
        this->SetupTweak(xtsTweak, currentSector, sectorAddress);

        while(pos < size) {
            /* XOR Encrypted Tweak with Input */
            for(uint8_t i = 0; i < Aes128BlockLength; i++) {
                tmp[i] = xtsTweak[i] ^ inData[i+pos];
            }

            /* Encrypt Data with key1 */
            m_EcbEncrypterKey1.DecryptBlock(tmp, tmp);

            /* XOR Tweak with output */
            for(uint8_t i = 0; i < Aes128BlockLength; i++) {
                outData[i+pos] = tmp[i] ^ xtsTweak[i];
            }

            /* Multiply tweak */
            this->GFMul(xtsTweak, xtsTweak);

            /* Update position and sector address */
            pos           += Aes128BlockLength;
            sectorAddress += Aes128BlockLength;

            /* Reset tweak if needed */
            if(sectorAddress >= m_AesSectorSize && (pos < size)) {
                currentSector++;
                sectorAddress = 0;
                this->SetupTweak(xtsTweak, currentSector, sectorAddress);
            }
        }

        /* Return */
        return Result_Success;
    }
}
