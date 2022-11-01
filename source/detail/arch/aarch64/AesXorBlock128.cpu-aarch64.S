.text

.global _ZN6crypto6detail14AesXorBlock128EPvPKvS3_

// void crypto::detail::AesXorBlock(void* pOut, const void* pIn1, const void* pIn2)
// X0[in] void* pOut
// X1[in] const void* pIn1
// X2[in] const void* pIn2
_ZN6crypto6detail14AesXorBlock128EPvPKvS3_:
    ldr     Q0, [X1]
    ldr     Q1, [X2]
    eor     Q0, Q0, Q1
    str     Q0, [X1]
    str     Q1, [X2]
    ret
