#pragma once
#include <inttypes.h>
#include <AesLookupTables.h>
#include <AesCommon128.h>
#include <wmmintrin.h>

#if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))
#endif
namespace crypto {
    class AesEcb128 {
        private:
            uint8_t m_AesRoundKeys[11][16];

        private:
    #if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
            __m128i m_Amd64RoundKeys[11];
            __m128i m_Amd64InvRoundKeys[11];
    #endif

        /* Generic Impl */
        private:
            void ExpandKeyGeneric();
            void EncryptBlockGeneric(uint8_t* output, const uint8_t* input);
            void DecryptBlockGeneric(uint8_t* output, const uint8_t* input);

        /* x86_64 AES-NI Impl */
    #if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
        private: 
            void ExpandKeyAmd64();
            void EncryptBlockAmd64(__m128i* output, const __m128i* input);
            void DecryptBlockAmd64(__m128i* output, const __m128i* input);
    #endif

        public:
            void Initialize(const void* key) {
                /* Copy Key */
    #if (defined(__x86_64__) || defined(_M_X64)) && (AES_ENABLE_HW_ACCEL == true)
                m_Amd64RoundKeys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
                this->ExpandKeyAmd64();
    #else
                std::memcpy(m_AesRoundKeys[0], key, Aes128BlockLength);
                this->ExpandKeyGeneric();
    #endif
            }

            void Finalize() {
                /* Wipe Key */
                memset(m_AesRoundKeys, 0, Aes128RoundKeyArraySize);
            }

        public:
            /* Constructor */
            AesEcb128() { /* ... */ }
            AesEcb128(const void* key) {
                this->Initialize(key);
            }

            /* Destructor */
            ~AesEcb128() {
                this->Finalize();
            }

        public:
            /* ECB Encrypt Single Block */
            Aes128Result EncryptBlock(void* output, const void* input);

            /* ECB Decrypt Single Block */
            Aes128Result DecryptBlock(void* output, const void* input);

            /* ECB Encrypt Data */
            Aes128Result EncryptData(void* output, const void* input, const size_t size);

            /* ECB Decrypt Data */
            Aes128Result DecryptData(void* output, const void* input, const size_t size);
    };
}
