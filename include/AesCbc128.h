#pragma once
#include <AesCommon128.h>
#include <AesEcb128.h>
#include <inttypes.h>

namespace crypto {
    class AesCbc128 {
        private:
            crypto::AesEcb128 m_EcbEncrypter;
            uint8_t m_AesIv[16];
            uint8_t m_AesStoredIv[16];

        public:
            void Initialize(const void* key, const void* iv) {
                /* Init ECB Encrypter */
                m_EcbEncrypter.Initialize(key);

                /* Copy IV */
                std::memcpy(m_AesIv, iv, Aes128BlockLength);
                std::memcpy(m_AesStoredIv, iv, Aes128BlockLength);
            }

            void Finalize() {
                /* Finalize ECB Encrypter */
                m_EcbEncrypter.Finalize();

                /* Wipe IV */
                std::memset(m_AesIv, 0, Aes128BlockLength);
                std::memset(m_AesStoredIv, 0, Aes128BlockLength);
            }

        public:
            /* Constructor */
            AesCbc128() { /* ... */ }
            AesCbc128(const void* key, const void* iv) : m_EcbEncrypter(key) { 
                std::memcpy(m_AesIv, iv, Aes128BlockLength);
                std::memcpy(m_AesStoredIv, iv, Aes128BlockLength);
            }

    #if AES_WIPE_KEYS_ON_DESTRUCTION == true
            /* Destructor */
            ~AesCbc128() {
                std::memset(m_AesIv, 0, Aes128BlockLength);
                std::memset(m_AesStoredIv, 0, Aes128BlockLength);
            }
    #endif

        public:
            /* CBC Encrypt Data */
            Aes128Result EncryptData(void* output, const void* input, const size_t size, const bool saveIv, const bool useStoredIv);

            /* CBC Decrypt Data */
            Aes128Result DecryptData(void* output, const void* input, const size_t size, const bool saveIv, const bool useStoredIv);
    };
}
