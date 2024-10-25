/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>
#include <arm_neon.h>

static const uint32_t raSha1K[16]  __attribute__((__aligned__(16))) = {
    0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999,
    0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1,
    0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 
    0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6
};

static void RaSha1Process_arm64(struct RaSha1Ctx *ctx, const uint8_t data[64])
{
    //  v16: abcd
    //  v17: e
    //  v12: abde (working)
    //  v13, v14: e (working)
    //  v4~v7: w0 ~ w15
    //  v8~v11: k0 ~ k3
    //  v15: temp

    __asm__ __volatile__ (
        "   mov     x4, %0\n"
        "   ld1     {v16.4s}, [x4], #16\n"        // abcd
        "   ld1     {v17.4s}, [x4]\n"             // e
        "   mov     v12.16b, v16.16b\n"           // abcd (working)
        "   mov     v13.16b, v17.16b\n"           // e (working)
        "\n"
        "   "
        "   mov     x4, %[raSha1K]\n"
        "   ld1     {v8.4s}, [x4], #16\n"        // k0
        "   ld1     {v9.4s}, [x4], #16\n"        // k1
        "   ld1     {v10.4s}, [x4], #16\n"       // k2
        "   ld1     {v11.4s}, [x4], #16\n"       // k3
        "\n"
        "   mov     x4, %[data]\n"
        "   ld1     {v4.16b}, [x4], 16\n"        // w0...w3
        "   ld1     {v5.16b}, [x4], 16\n"        // w4...w7
        "   ld1     {v6.16b}, [x4], 16\n"        // w8...w11
        "   ld1     {v7.16b}, [x4], 16\n"        // w12..w15
        "   rev32   v4.16b, v4.16b\n"
        "   rev32   v5.16b, v5.16b\n"
        "   rev32   v6.16b, v6.16b\n"
        "   rev32   v7.16b, v7.16b\n"
        "\n"                                    // F=(D ^ (B & (C ^ D))), K=0x5a827999
        "   add     v15.4s, v4.4s, v8.4s\n"     // r0...r3
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1c   q12, s13, v15.4s\n"
        "\n"
        "   add     v15.4s, v5.4s, v8.4s\n"     // r4...r7
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1c   q12, s14, v15.4s\n"
        "\n"
        "   add     v15.4s, v6.4s, v8.4s\n"     // r8...r11
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1c   q12, s13, v15.4s\n"
        "\n"
        "   add     v15.4s, v7.4s, v8.4s\n"     // r12...r15
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1c   q12, s14, v15.4s\n"
        "\n"
        "   sha1su0 v4.4s, v5.4s, v6.4s\n"      // r16...r19
        "   sha1su1 v4.4s, v7.4s\n"
        "   add     v15.4s, v4.4s, v8.4s\n"
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1c   q12, s13, v15.4s\n"
        "\n"                                    // F=(B ^ C ^ D), K=0x6ed9eba1
        "   sha1su0 v5.4s, v6.4s, v7.4s\n"      // r20...r23
        "   sha1su1 v5.4s, v4.4s\n"
        "   add     v15.4s, v5.4s, v9.4s\n"     // add k1
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1p   q12, s14, v15.4s\n"
        "\n"
        "   sha1su0 v6.4s, v7.4s, v4.4s\n"      // r24...r27
        "   sha1su1 v6.4s, v5.4s\n"
        "   add     v15.4s, v6.4s, v9.4s\n"     // add k1
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1p   q12, s13, v15.4s\n"
        "\n"
        "   sha1su0 v7.4s, v4.4s, v5.4s\n"      // r28...r31
        "   sha1su1 v7.4s, v6.4s\n"
        "   add     v15.4s, v7.4s, v9.4s\n"     // add k1
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1p   q12, s14, v15.4s\n"
        "\n"
        "   sha1su0 v4.4s, v5.4s, v6.4s\n"      // r32...r35
        "   sha1su1 v4.4s, v7.4s\n"
        "   add     v15.4s, v4.4s, v9.4s\n"     // add k1
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1p   q12, s13, v15.4s\n"
        "\n"
        "   sha1su0 v5.4s, v6.4s, v7.4s\n"      // r36...r39
        "   sha1su1 v5.4s, v4.4s\n"
        "   add     v15.4s, v5.4s, v9.4s\n"    // add k1
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1p   q12, s14, v15.4s\n"
        "\n"                                    // F=((B & (C | D)) | (C & D)), K=0x8f1bbcdc
        "   sha1su0 v6.4s, v7.4s, v4.4s\n"      // r40...r43
        "   sha1su1 v6.4s, v5.4s\n"
        "   add     v15.4s, v6.4s, v10.4s\n"    // add k1
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1m   q12, s13, v15.4s\n"
        "\n"
        "   sha1su0 v7.4s, v4.4s, v5.4s\n"      // r44...r47
        "   sha1su1 v7.4s, v6.4s\n"
        "   add     v15.4s, v7.4s, v10.4s\n"    // add k1
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1m   q12, s14, v15.4s\n"
        "\n"
        "   sha1su0 v4.4s, v5.4s, v6.4s\n"      // r48...r51
        "   sha1su1 v4.4s, v7.4s\n"
        "   add     v15.4s, v4.4s, v10.4s\n"    // add k1
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1m   q12, s13, v15.4s\n"
        "\n"
        "   sha1su0 v5.4s, v6.4s, v7.4s\n"      // r52...r55
        "   sha1su1 v5.4s, v4.4s\n"
        "   add     v15.4s, v5.4s, v10.4s\n"    // add k1
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1m   q12, s14, v15.4s\n"
        "\n"
        "   sha1su0 v6.4s, v7.4s, v4.4s\n"      // r56...r59
        "   sha1su1 v6.4s, v5.4s\n"
        "   add     v15.4s, v6.4s, v10.4s\n"    // add k1
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1m   q12, s13, v15.4s\n"
        "\n"                                    // F=(B ^ C ^ D), K=0xca62c1d6
        "   sha1su0 v7.4s, v4.4s, v5.4s\n"      // r60...r63
        "   sha1su1 v7.4s, v6.4s\n"
        "   add     v15.4s, v7.4s, v11.4s\n"    // add k1
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1p   q12, s14, v15.4s\n"
        "\n" 
        "   sha1su0 v4.4s, v5.4s, v6.4s\n"      // r64...r67
        "   sha1su1 v4.4s, v7.4s\n"
        "   add     v15.4s, v4.4s, v11.4s\n"    // add k1
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1p   q12, s13, v15.4s\n"
        "\n"
        "   sha1su0 v5.4s, v6.4s, v7.4s\n"      // r68...r71
        "   sha1su1 v5.4s, v4.4s\n"
        "   add     v15.4s, v5.4s, v11.4s\n"    // add k1
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1p   q12, s14, v15.4s\n"
        "\n"
        "   sha1su0 v6.4s, v7.4s, v4.4s\n"      // r72...r75
        "   sha1su1 v6.4s, v5.4s\n"
        "   add     v15.4s, v6.4s, v11.4s\n"    // add k1
        "   sha1h   s14, s12\n"                 // s14 = nexte
        "   sha1p   q12, s13, v15.4s\n"
        "\n"
        "   sha1su0 v7.4s, v4.4s, v5.4s\n"      // r76...r79
        "   sha1su1 v7.4s, v6.4s\n"
        "   add     v15.4s, v7.4s, v11.4s\n"    // add k1
        "   sha1h   s13, s12\n"                 // s13 = nexte
        "   sha1p   q12, s14, v15.4s\n"
        "\n"
        "   add     v16.4s, v16.4s, v12.4s\n"
        "   add     v17.4s, v17.4s, v13.4s\n"
        "\n"
        "   mov     x4, %0\n"
        "   st1     {v16.4s}, [x4], #16\n"
        "   st1     {v17.s}[0], [x4]\n"
        :
        : "r" (ctx->h), [data] "r" (data), [raSha1K] "r" (raSha1K)
        : "x4", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17"
    );
}

void RaSha1CheckForInstructionSet(struct RaSha1Ctx *ctx)
{
    uint64_t id_aa64isar0;
    // Read the ID_AA64ISAR0_EL1 system register to check for SHA-1 support
    __asm__ __volatile__ (
        "mrs %0, ID_AA64ISAR0_EL1"
        : "=r" (id_aa64isar0)
    );

    // Check if the SHA-1 instructions are supported (bits [11:8] should be 0b0001)
    if (((id_aa64isar0 >> 8) & 0xF) == 1) {
        ctx->fnRaSha1Process = RaSha1Process_arm64;
    }
}
