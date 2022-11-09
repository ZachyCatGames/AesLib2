#include "test_UpdateCounter.h"
#include <AesLib/AesCtrCounter.h>
#include <limits>

namespace crypto {
namespace test {

void TestCounterUpdate() {
    uint8_t ctr[16] = {0};
    ctr[15] = 1;
    constexpr uint64_t updateAmount = std::numeric_limits<uint64_t>::max();

    crypto::UpdateCounter(ctr, updateAmount);

    for(int i = 0; i < 16; ++i) {
        printf("%02x", ctr[i]);
    }
    printf("\n");
}

} // namespace test
} // namespace crypto