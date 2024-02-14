#include <AesLib/AesCtrCounter.h>
#include <bit>
#include <cstdio>

namespace crypto {

void UpdateCounter(void* pData, uint64_t amount) {
    uint64_t* pData64 = static_cast<uint64_t*>(pData);
    uint64_t initialData[2] = {pData64[0], pData64[1]};
    uint64_t dataSwapped[2] = {std::byteswap(pData64[0]), std::byteswap(pData64[1])};
    uint64_t amountSwapped = std::byteswap(amount);

    /* Add first half to amount. */
    pData64[1] = std::byteswap(amount + dataSwapped[1]);

    /* Check if pData is smaller than it initially was. */
    if(std::byteswap(pData64[1]) <= dataSwapped[1]) {
        pData64[0] = std::byteswap(dataSwapped[0] + 1);
    }
}

} // namespace crypto
