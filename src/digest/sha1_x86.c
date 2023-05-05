#include <racrypt.h>

static void RaSha1Process_x86(struct RaSha1Ctx *ctx, const uint8_t data[64])
{
	const static uint8_t order_byte[] __attribute__((__aligned__(16))) = { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
	uint8_t xmm_save[16 * 8] __attribute__((__aligned__(16)));

	__asm__ __volatile__ (
		"movdqa %%xmm0, %3\n\t"
		"movdqa %%xmm1, 0x10 %3\n\t"
		"movdqa %%xmm2, 0x20 %3\n\t"
		"movdqa %%xmm3, 0x30 %3\n\t"
		"movdqa %%xmm4, 0x40 %3\n\t"
		"movdqa %%xmm5, 0x50 %3\n\t"
		"movdqa %%xmm6, 0x60 %3\n\t"
		"movdqa %%xmm7, 0x70 %3\n\t"

		"movdqu (%0), %%xmm0\n\t"				// abcd
		"movd   16(%0), %%xmm1\n\t"				// e
		"movdqu (%1), %%xmm3\n\t"				// w0...w3
		"movdqu 16(%1), %%xmm4\n\t"				// w4...w7
		"movdqu 32(%1), %%xmm5\n\t"				// w8...w11
		"movdqu 48(%1), %%xmm6\n\t"				// w12..w15

		"pshufd $0b00011011, %%xmm0, %%xmm0\n\t"	// change word order
		"pshufd $0b00011011, %%xmm1, %%xmm1\n\t"	// change word order
		"pshufb %2, %%xmm3\n\t"					// endian change
		"pshufb %2, %%xmm4\n\t"					// endian change
		"pshufb %2, %%xmm5\n\t"					// endian change
		"pshufb %2, %%xmm6\n\t"					// endian change

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"paddd %%xmm3, %%xmm1\n\t"				// xmm1 = (w0 + e)...w3
		"sha1rnds4 $0, %%xmm1, %%xmm0\n\t"		// r0~r3

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm4, %%xmm2\n\t"			// xmm2 = (w4 + e)...w7
		"sha1rnds4 $0, %%xmm2, %%xmm0\n\t"		// r4~r7

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm5, %%xmm1\n\t"			// xmm1 = (w8 + e)...w11
		"sha1rnds4 $0, %%xmm1, %%xmm0\n\t"		// r8~r11

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm6, %%xmm2\n\t"			// xmm2 = (w12 + e)...w15
		"sha1rnds4 $0, %%xmm2, %%xmm0\n\t"		// r12~r15

////////////////////
		"sha1msg1 %%xmm4, %%xmm3\n\t"
		"pxor %%xmm5, %%xmm3\n\t"
		"sha1msg2 %%xmm6, %%xmm3\n\t"

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm3, %%xmm1\n\t"
		"sha1rnds4 $0, %%xmm1, %%xmm0\n\t"		// r16~r19

////////////////////
		"sha1msg1 %%xmm5, %%xmm4\n\t"
		"pxor %%xmm6, %%xmm4\n\t"
		"sha1msg2 %%xmm3, %%xmm4\n\t"

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm4, %%xmm2\n\t"
		"sha1rnds4 $1, %%xmm2, %%xmm0\n\t"		// r20~r23

		"sha1msg1 %%xmm6, %%xmm5\n\t"
		"pxor %%xmm3, %%xmm5\n\t"
		"sha1msg2 %%xmm4, %%xmm5\n\t"

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm5, %%xmm1\n\t"
		"sha1rnds4 $1, %%xmm1, %%xmm0\n\t"		// r24~r27

		"sha1msg1 %%xmm3, %%xmm6\n\t"
		"pxor %%xmm4, %%xmm6\n\t"
		"sha1msg2 %%xmm5, %%xmm6\n\t"

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm6, %%xmm2\n\t"
		"sha1rnds4 $1, %%xmm2, %%xmm0\n\t"		// r28~r31

		"sha1msg1 %%xmm4, %%xmm3\n\t"
		"pxor %%xmm5, %%xmm3\n\t"
		"sha1msg2 %%xmm6, %%xmm3\n\t"

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm3, %%xmm1\n\t"
		"sha1rnds4 $1, %%xmm1, %%xmm0\n\t"		// r32~r35

		"sha1msg1 %%xmm5, %%xmm4\n\t"
		"pxor %%xmm6, %%xmm4\n\t"
		"sha1msg2 %%xmm3, %%xmm4\n\t"

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm4, %%xmm2\n\t"
		"sha1rnds4 $1, %%xmm2, %%xmm0\n\t"		// r36~r39

////////////////////
		"sha1msg1 %%xmm6, %%xmm5\n\t"
		"pxor %%xmm3, %%xmm5\n\t"
		"sha1msg2 %%xmm4, %%xmm5\n\t"

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm5, %%xmm1\n\t"
		"sha1rnds4 $2, %%xmm1, %%xmm0\n\t"		// r40~r43

		"sha1msg1 %%xmm3, %%xmm6\n\t"
		"pxor %%xmm4, %%xmm6\n\t"
		"sha1msg2 %%xmm5, %%xmm6\n\t"

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm6, %%xmm2\n\t"
		"sha1rnds4 $2, %%xmm2, %%xmm0\n\t"		// r44~r47

		"sha1msg1 %%xmm4, %%xmm3\n\t"
		"pxor %%xmm5, %%xmm3\n\t"
		"sha1msg2 %%xmm6, %%xmm3\n\t"

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm3, %%xmm1\n\t"
		"sha1rnds4 $2, %%xmm1, %%xmm0\n\t"		// r48~r51

		"sha1msg1 %%xmm5, %%xmm4\n\t"
		"pxor %%xmm6, %%xmm4\n\t"
		"sha1msg2 %%xmm3, %%xmm4\n\t"

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm4, %%xmm2\n\t"
		"sha1rnds4 $2, %%xmm2, %%xmm0\n\t"		// r52~r55

		"sha1msg1 %%xmm6, %%xmm5\n\t"
		"pxor %%xmm3, %%xmm5\n\t"
		"sha1msg2 %%xmm4, %%xmm5\n\t"

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm5, %%xmm1\n\t"
		"sha1rnds4 $2, %%xmm1, %%xmm0\n\t"		// r56~r59

////////////////////
		"sha1msg1 %%xmm3, %%xmm6\n\t"
		"pxor %%xmm4, %%xmm6\n\t"
		"sha1msg2 %%xmm5, %%xmm6\n\t"

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm6, %%xmm2\n\t"
		"sha1rnds4 $3, %%xmm2, %%xmm0\n\t"		// r60~r63

		"sha1msg1 %%xmm4, %%xmm3\n\t"
		"pxor %%xmm5, %%xmm3\n\t"
		"sha1msg2 %%xmm6, %%xmm3\n\t"

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm3, %%xmm1\n\t"
		"sha1rnds4 $3, %%xmm1, %%xmm0\n\t"		// r64~r67

		"sha1msg1 %%xmm5, %%xmm4\n\t"
		"pxor %%xmm6, %%xmm4\n\t"
		"sha1msg2 %%xmm3, %%xmm4\n\t"

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm4, %%xmm2\n\t"
		"sha1rnds4 $3, %%xmm2, %%xmm0\n\t"		// r68~r71

		"sha1msg1 %%xmm6, %%xmm5\n\t"
		"pxor %%xmm3, %%xmm5\n\t"
		"sha1msg2 %%xmm4, %%xmm5\n\t"

		"movdqa %%xmm0, %%xmm2\n\t"				// abcd_save
		"sha1nexte %%xmm5, %%xmm1\n\t"
		"sha1rnds4 $3, %%xmm1, %%xmm0\n\t"		// r72~r75

		"sha1msg1 %%xmm3, %%xmm6\n\t"
		"pxor %%xmm4, %%xmm6\n\t"
		"sha1msg2 %%xmm5, %%xmm6\n\t"

		"movdqa %%xmm0, %%xmm1\n\t"				// abcd_save
		"sha1nexte %%xmm6, %%xmm2\n\t"
		"sha1rnds4 $3, %%xmm2, %%xmm0\n\t"		// r76~r79

		"movdqu (%0), %%xmm2\n\t"
		"pshufd $0b00011011, %%xmm0, %%xmm0\n\t"	// change word order
		"paddd %%xmm0, %%xmm2\n\t"
		"movdqu %%xmm2, (%0)\n\t"				// a, b, c, d

		"pxor %%xmm3, %%xmm3\n\t"
		"sha1nexte %%xmm3, %%xmm1\n\t"

		"movd 16(%0), %%xmm2\n\t"
		"pshufd $0b00011011, %%xmm1, %%xmm1\n\t"	// change word order
		"paddd %%xmm1, %%xmm2\n\t"
		"movd %%xmm2, 16(%0)\n\t"				// e

		"movdqa %3, %%xmm0\n\t"
		"movdqa 0x10 %3, %%xmm1\n\t"
		"movdqa 0x20 %3, %%xmm2\n\t"
		"movdqa 0x30 %3, %%xmm3\n\t"
		"movdqa 0x40 %3, %%xmm4\n\t"
		"movdqa 0x50 %3, %%xmm5\n\t"
		"movdqa 0x60 %3, %%xmm6\n\t"
		"movdqa 0x70 %3, %%xmm7\n\t"
		:
		: "r" (ctx->h), "r" (data), "m" (*order_byte), "m" (*xmm_save)
		: "memory");
}

void RaSha1CheckForIntelShaExtensions( struct RaSha1Ctx *ctx )
{
	int a, b, c, d;

	// Look for CPUID.7.0.EBX[29]
	// EAX = 7, ECX = 0
	a = 7;
	c = 0;

	__asm__ volatile (
		"cpuid"
		: "=a"( a ), "=b"( b ), "=c"( c ), "=d"( d )
		: "a"( a ), "c"( c )
		);
	// Intel SHA Extensions feature bit is EBX[29]
	if ( ( b >> 29 ) & 1 ) {
		ctx->fnRaSha1Process = RaSha1Process_x86;
	}
}

