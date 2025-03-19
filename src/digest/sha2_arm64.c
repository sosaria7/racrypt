/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>
#include <arm_neon.h>

static const uint32_t raSha256K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void RaSha256Process_arm64(struct RaSha2Ctx *ctx, const uint8_t data[64])
{
    //  v16: abcd
    //  v17: efgh
    //  v12: abcd (working)
    //  v13: efgh (working)
    //  v4~v7: w0 ~ w15
    //  v8~v11: k0 ~ k15 ... k48 ~ k63
    //  v14: temp
    //  v15: temp

    __asm__ __volatile__ (
        "   mov         x4, %0\n"
        "   ld1         {v12.2d-v15.2d}, [x4], #64\n" // abcd, efgh
        "   xtn         v16.2s, v12.2d\n"       // h[0], h[1]
        "   xtn2        v16.4s, v13.2d\n"       // h[2], h[3]
        "   xtn         v17.2s, v14.2d\n"       // h[4], h[5]
        "   xtn2        v17.4s, v15.2d\n"       // h[6], h[7]
        "   mov         v12.16b, v16.16b\n"           // abcd (working)
        "   mov         v13.16b, v17.16b\n"           // efgh (working)
        "\n"
        "   mov         x4, %[data]\n"
        "   ld1         {v4.16b-v7.16b}, [x4], #64\n"   // w0...w3 / w4...w7 / w8...w11 / w12...w15
        "   rev32       v4.16b, v4.16b\n"
        "   rev32       v5.16b, v5.16b\n"
        "   rev32       v6.16b, v6.16b\n"
        "   rev32       v7.16b, v7.16b\n"
        "\n"
        "   mov         x4, %[raSha256K]\n"
        "   ld1         {v8.4s-v11.4s}, [x4], #64\n"  // k0~k15
        "\n"
        "   add         v15.4s, v4.4s, v8.4s\n"     // r0...r3
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   add         v15.4s, v5.4s, v9.4s\n"     // r4...r7
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   add         v15.4s, v6.4s, v10.4s\n"     // r8...r11
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   add         v15.4s, v7.4s, v11.4s\n"     // r12...r15
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   ld1         {v8.4s-v11.4s}, [x4], #64\n"  // k16~k31
        "\n"
        "   sha256su0   v4.4s, v5.4s\n"      // r16...r19
        "   sha256su1   v4.4s, v6.4s, v7.4s\n"
        "   add         v15.4s, v4.4s, v8.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v5.4s, v6.4s\n"      // r20...r23
        "   sha256su1   v5.4s, v7.4s, v4.4s\n"
        "   add         v15.4s, v5.4s, v9.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v6.4s, v7.4s\n"      // r24...r27
        "   sha256su1   v6.4s, v4.4s, v5.4s\n"
        "   add         v15.4s, v6.4s, v10.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v7.4s, v4.4s\n"      // r28...r31
        "   sha256su1   v7.4s, v5.4s, v6.4s\n"
        "   add         v15.4s, v7.4s, v11.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   ld1         {v8.4s-v11.4s}, [x4], #64\n"  // k32~k47
        "\n"
        "   sha256su0   v4.4s, v5.4s\n"      // r32...r35
        "   sha256su1   v4.4s, v6.4s, v7.4s\n"
        "   add         v15.4s, v4.4s, v8.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v5.4s, v6.4s\n"      // r36...r39
        "   sha256su1   v5.4s, v7.4s, v4.4s\n"
        "   add         v15.4s, v5.4s, v9.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v6.4s, v7.4s\n"      // r40...r43
        "   sha256su1   v6.4s, v4.4s, v5.4s\n"
        "   add         v15.4s, v6.4s, v10.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v7.4s, v4.4s\n"      // r44...r47
        "   sha256su1   v7.4s, v5.4s, v6.4s\n"
        "   add         v15.4s, v7.4s, v11.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   ld1         {v8.4s-v11.4s}, [x4], #64\n"  // k48~k63
        "\n"
        "   sha256su0   v4.4s, v5.4s\n"      // r48...r51
        "   sha256su1   v4.4s, v6.4s, v7.4s\n"
        "   add         v15.4s, v4.4s, v8.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v5.4s, v6.4s\n"      // r52...r55
        "   sha256su1   v5.4s, v7.4s, v4.4s\n"
        "   add         v15.4s, v5.4s, v9.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v6.4s, v7.4s\n"      // r56...r59
        "   sha256su1   v6.4s, v4.4s, v5.4s\n"
        "   add         v15.4s, v6.4s, v10.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   sha256su0   v7.4s, v4.4s\n"      // r60...r63
        "   sha256su1   v7.4s, v5.4s, v6.4s\n"
        "   add         v15.4s, v7.4s, v11.4s\n"
        "   mov         v14.16b, v12.16b\n"
        "   sha256h     q12, q13, v15.4s\n"
        "   sha256h2    q13, q14, v15.4s\n"
        "\n"
        "   add         v16.4s, v16.4s, v12.4s\n"
        "   add         v17.4s, v17.4s, v13.4s\n"
        "\n"
        "   mov         x4, %0\n"
        "   uxtl        v12.2d, v16.2s\n"           // h[0], h[1]
        "   uxtl2       v13.2d, v16.4s\n"           // h[2], h[3]
        "   uxtl        v14.2d, v17.2s\n"           // h[4], h[5]
        "   uxtl2       v15.2d, v17.4s\n"           // h[6], h[7]
        "   st1         {v12.2d-v15.2d}, [x4], #64\n"
        :
        : "r" (ctx->h), [data] "r" (data), [raSha256K] "r" (raSha256K)
        : "x4", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17"
    );
}

void RaSha256CheckForInstructionSet( struct RaSha2Ctx *ctx )
{
#ifdef __APPLE__
    ctx->fn.fnRaSha256Process = RaSha256Process_arm64;
#else
    uint64_t id_aa64isar0;
    // Read the ID_AA64ISAR0_EL1 system register to check for SHA-2 support
    __asm__ __volatile__ (
        "mrs %0, ID_AA64ISAR0_EL1"
        : "=r" (id_aa64isar0)
    );

    // Check if the SHA-2 instructions are supported (bits [15:12] should be 0b0001 or 0b0010)
    if (((id_aa64isar0 >> 12) & 0xF) != 0b0000) {
        ctx->fn.fnRaSha256Process = RaSha256Process_arm64;
    }
#endif
}

