#include <AesLib/detail/AesXtsNTweakHandler.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/AesCommon.h>
#include <bit>

namespace crypto {
namespace detail {

AesXtsNTweakHandler::AesXtsNTweakHandler(UniqueEncryptor&& pEnc) :
    m_pEncryptor(std::move(pEnc)) {}

AesXtsNTweakHandler::~AesXtsNTweakHandler() = default;

void AesXtsNTweakHandler::Initialize(const void* pKey, size_t keySize) {
    m_pEncryptor->Initialize(pKey, keySize);
}

void AesXtsNTweakHandler::SetupTweak(void* pOut, size_t curSector, size_t sectAddr) {
    uint64_t* xtsTweak = static_cast<uint64_t*>(pOut);

    xtsTweak[0] = 0;
    xtsTweak[1] = std::byteswap(curSector);

    /* Encrypt Tweak with key2 */
    m_pEncryptor->EncryptBlock(reinterpret_cast<uint8_t*>(xtsTweak), reinterpret_cast<uint8_t*>(xtsTweak));

    /* Update tweak if needed */
    for (size_t i = sectAddr / AesBlockLength; i < 0; i--) {
        GFMul(xtsTweak, xtsTweak);
    }
}

} // namespace detail
} // namespace crypto
