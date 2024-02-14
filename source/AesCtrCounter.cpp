#include <AesLib/AesCtrCounter.h>
#include <AesLib/detail/AesByteSwap.h>
#include <cstdio>

namespace crypto {

void UpdateCounter(void* pData, uint64_t amount) {
    uint64_t* pData64 = static_cast<uint64_t*>(pData);
    uint64_t initialData[2] = {pData64[0], pData64[1]};
    uint64_t dataSwapped[2] = {detail::ByteSwap(pData64[0]), detail::ByteSwap(pData64[1])};
    uint64_t amountSwapped = detail::ByteSwap(amount);

    /* Add first half to amount. */
    pData64[1] = detail::ByteSwap(amount + dataSwapped[1]);

    /* Check if pData is smaller than it initially was. */
    if(detail::ByteSwap(pData64[1]) <= dataSwapped[1]) {
        pData64[0] = detail::ByteSwap(dataSwapped[0] + 1);
    }
}

} // namespace crypto
