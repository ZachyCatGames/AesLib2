#include "test_AesEcbTest.h"
#include "test_AesCbcTest.h"
#include "test_Aes256Exp.h"

int main(int argc, char** argv) {
    crypto::test::TestExperimentalAes256();
    return 0;

    /* Test ECB mode. */
    crypto::test::TestAesEcbMode();

    /* Test CBC mode. */
    crypto::test::TestAesCbcMode();
}
