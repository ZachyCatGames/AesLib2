#pragma once
#include <AesCommon128.h>
#include <AesEcb128.h>
#include <inttypes.h>

namespace crypto {
    class AesXts128 {
        private:
            crypto::AesEcb128 m_EcbEncrypterKey1;
            crypto::AesEcb128 m_EcbEncrypterKey2;
            size_t m_AesSectorSize;
            bool m_IsNintendo;
    
        public:
            void Initialize(const void* key1, const void* key2, const size_t sectorSize, const bool isNintendo) {
                /* Initialize ECB Encrypters */
                m_EcbEncrypterKey1.Initialize(key1);
                m_EcbEncrypterKey2.Initialize(key2);
    
                /* Copy Extra Info */
                m_AesSectorSize = sectorSize;
                m_IsNintendo = isNintendo;
            }
            
            void Finalize() {
                /* Finalize ECB Encrypters */
                m_EcbEncrypterKey1.Finalize();
                m_EcbEncrypterKey2.Finalize();
            }
    
        public:
            /* Constructor */
            AesXts128() { /* ... */ }
            AesXts128(const void* key1, const void* key2, const size_t sectorSize, const bool isNintendo) : m_EcbEncrypterKey1(key1), m_EcbEncrypterKey2(key2) {
                m_AesSectorSize = sectorSize;
                m_IsNintendo = isNintendo;
            }
    
        private:
            void GFMul(void* out, const void* in);
            void SetupTweak(void* tweak, const size_t currentSector, const size_t sectorAddress);
    
        public:
            /* XTS Encrypt Data */
            Aes128Result EncryptData(void* output, const void* input, const size_t address, const size_t size);
    
            /* XTS Decrypt Data */
            Aes128Result DecryptData(void* output, const void* input, const size_t address, const size_t size);
    };
}
