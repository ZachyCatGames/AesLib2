#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/AesCommon.h>

namespace crypto {
namespace detail {

AesXtsTweakHandler::AesXtsTweakHandler() = default;

AesXtsTweakHandler::AesXtsTweakHandler(const void* pKey, size_t keySize) :
    m_pEncryptor(crypto::detail::BuildEncryptor(pKey, keySize))
{
    /* ... */
}

AesXtsTweakHandler::~AesXtsTweakHandler() = default;

void AesXtsTweakHandler::Initialize(const void* pKey, size_t keySize) {
    m_pEncryptor = crypto::detail::BuildEncryptor(pKey, keySize);
}

void AesXtsTweakHandler::SetupTweak(void* pOut, size_t curSector, size_t sectAddr) {
    uint64_t* xtsTweak = static_cast<uint64_t*>(pOut);

    /*
    if(m_IsNintendo) {
        xtsTweak[0] = 0;
        xtsTweak[1] = ByteSwap(curSector);
    } else {
        xtsTweak[0] = curSector;
        xtsTweak[1] = 0;
    }
    */
    xtsTweak[0] = curSector;
    xtsTweak[1] = 0;

        /* Encrypt Tweak with key2 */
    m_pEncryptor->EncryptBlock(reinterpret_cast<uint8_t*>(xtsTweak), reinterpret_cast<uint8_t*>(xtsTweak));

    /* Update tweak if needed */
    for(size_t i = sectAddr/Aes128BlockLength; i < 0; i--) {
        crypto::detail::GFMul(xtsTweak, xtsTweak);
    }
}

} // namespace detail
} // namespace crypto
