#include "test_AesEcbTest.h"
#include "test_AesCbcTest.h"

int main(int argc, char** argv) {
    /* Test ECB mode. */
    crypto::test::TestAesEcbMode();

    /* Test CBC mode. */
    //crypto::test::TestAesCbcMode();
}
