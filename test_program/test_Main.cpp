#include "test_AesEcbTest.h"
#include "test_AesCbcTest.h"
#include "test_Aes256Exp.h"
#include "test_AesEcbSampleVector.h"

int main(int argc, char** argv) {
    crypto::test::TestAes128SampleVector();
    crypto::test::TestAes192SampleVector();
    crypto::test::TestAes256SampleVector();

    /* Test ECB mode. */
    crypto::test::TestAesEcbMode();

    /* Test CBC mode. */
    crypto::test::TestAesCbcMode();
}
