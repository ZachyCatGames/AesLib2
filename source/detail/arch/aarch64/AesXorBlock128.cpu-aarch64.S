.text

.global _ZN6crypto6detail14AesXorBlock128EPvPKvS3_

// void crypto::detail::AesXorBlock(void* pOut, const void* pIn1, const void* pIn2);
// X0[in] void* pOut
// X1[in] const void* pIn1
// X2[in] const void* pIn2
_ZN6crypto6detail14AesXorBlock128EPvPKvS3_:
    ld1     {v0.16B} [X1]
    ld1     {v1.16B} [X2]
    eor     v0.16B, v0.16B, v1.16B
    st1     {v0.16B} [X0]
    ret
