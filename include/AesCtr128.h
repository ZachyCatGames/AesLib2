#pragma once
#include <AesCommon128.h>
#include <AesEcb128.h>
#include <inttypes.h>

namespace crypto {
    class AesCtr128 {
        private:
            crypto::AesEcb128 m_EcbEncrypter;
            uint8_t m_AesCounter[16];
            uint8_t m_AesStoredCounter[16];

        private:
            void IncreaseStrCtr(size_t ammount);
            void DecreaseStrCtr(size_t ammount);

        public:
            void Initialize(const void* key, const void* ctr) {
                /* Initialize ECB Encrypter */
                m_EcbEncrypter.Initialize(key);

                /* Copy CTR */
                std::memcpy(m_AesCounter, ctr, Aes128BlockLength);
                std::memcpy(m_AesStoredCounter, ctr, Aes128BlockLength);
            }

            void Finalize() {
                /* Finalize ECB Encrypter */
                m_EcbEncrypter.Finalize();

                /* Wipe CTR */
                memset(m_AesCounter, 0, Aes128BlockLength);
                memset(m_AesStoredCounter, 0, Aes128BlockLength);
            }

        public:
            /* Constructor */
            AesCtr128() { /* ... */ }
            AesCtr128(const void* key, const void* ctr) : m_EcbEncrypter(key) {
                std::memcpy(m_AesCounter, ctr, Aes128BlockLength);
                std::memcpy(m_AesStoredCounter, ctr, Aes128BlockLength);
            }

            /* Destructor */
            ~AesCtr128() {
                memset(m_AesCounter, 0, Aes128BlockLength);
                memset(m_AesStoredCounter, 0, Aes128BlockLength);
            }

        public:
            /* Increment counter. */
            void IncrementStoredCounter(int64_t ammount); 

            /* CTR Crypt Block */
            Aes128Result CryptBlock(void* output, const void* input);

            /* CTR Crypt Data */
            Aes128Result CryptData(void* output, const void* input, const size_t size, const bool saveCtr, const bool useStoredCtr);

            /* CTR Crypt Data (don't store CTR) */
            inline Aes128Result CryptData(void* output, const void* input, const size_t size) {
                return CryptData(output, input, size, false, false);
            }

            /* CTR Crypt Data (store CTR) */
            inline Aes128Result CryptDataStoreCtr(void* output, const void* input, const size_t size) {
                return CryptData(output, input, size, true, true);
            }
    };
}
