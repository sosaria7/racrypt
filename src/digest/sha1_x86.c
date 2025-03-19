/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

static void RaSha1Process_x86(struct RaSha1Ctx *ctx, const uint8_t data[64])
{
	static const uint8_t order_byte[] __attribute__((__aligned__(16))) = { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
	uint8_t xmm_save[16 * 9];

	__asm__ __volatile__ (
		"	add			$0x0c, %[xmm_save]\n"
		"	shr			$4, %[xmm_save]\n"
		"	shl			$4, %[xmm_save]\n"
		"	movdqa		%%xmm0, (%[xmm_save])\n"
		"	movdqa		%%xmm1, 0x10(%[xmm_save])\n"
		"	movdqa		%%xmm2, 0x20(%[xmm_save])\n"
		"	movdqa		%%xmm3, 0x30(%[xmm_save])\n"
		"	movdqa		%%xmm4, 0x40(%[xmm_save])\n"
		"	movdqa		%%xmm5, 0x50(%[xmm_save])\n"
		"	movdqa		%%xmm6, 0x60(%[xmm_save])\n"
		"	movdqa		%%xmm7, 0x70(%[xmm_save])\n"
		"\n"
		"	movdqu		(%0), %%xmm0\n"					// abcd
		"	movd  		16(%0), %%xmm1\n"				// e
		"	movdqu		(%[data]), %%xmm3\n"			// w0...w3
		"	movdqu		16(%[data]), %%xmm4\n"			// w4...w7
		"	movdqu		32(%[data]), %%xmm5\n"			// w8...w11
		"	movdqu		48(%[data]), %%xmm6\n"			// w12..w15
		"\n"
		"	pshufd		$0b00011011, %%xmm0, %%xmm0\n"	// change word order
		"	pshufd		$0b00011011, %%xmm1, %%xmm1\n"	// change word order
		"	pshufb		%[order_byte], %%xmm3\n"		// endian change
		"	pshufb		%[order_byte], %%xmm4\n"		// endian change
		"	pshufb		%[order_byte], %%xmm5\n"		// endian change
		"	pshufb		%[order_byte], %%xmm6\n"		// endian change
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	paddd		%%xmm3, %%xmm1\n"				// xmm1 = (w0 + e)...w3
		"	sha1rnds4	$0, %%xmm1, %%xmm0\n"			// r0~r3
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm4, %%xmm2\n"				// xmm2 = (w4 + e)...w7
		"	sha1rnds4	$0, %%xmm2, %%xmm0\n"			// r4~r7
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm5, %%xmm1\n"				// xmm1 = (w8 + e)...w11
		"	sha1rnds4	$0, %%xmm1, %%xmm0\n"			// r8~r11
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm6, %%xmm2\n"				// xmm2 = (w12 + e)...w15
		"	sha1rnds4	$0, %%xmm2, %%xmm0\n"			// r12~r15
		"\n"
////////////////////
		"	sha1msg1	%%xmm4, %%xmm3\n"
		"	pxor		%%xmm5, %%xmm3\n"
		"	sha1msg2	%%xmm6, %%xmm3\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm3, %%xmm1\n"
		"	sha1rnds4	$0, %%xmm1, %%xmm0\n"			// r16~r19
		"\n"
////////////////////
		"	sha1msg1	%%xmm5, %%xmm4\n"
		"	pxor		%%xmm6, %%xmm4\n"
		"	sha1msg2	%%xmm3, %%xmm4\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm4, %%xmm2\n"
		"	sha1rnds4	$1, %%xmm2, %%xmm0\n"			// r20~r23
		"\n"
		"	sha1msg1	%%xmm6, %%xmm5\n"
		"	pxor		%%xmm3, %%xmm5\n"
		"	sha1msg2	%%xmm4, %%xmm5\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm5, %%xmm1\n"
		"	sha1rnds4	$1, %%xmm1, %%xmm0\n"			// r24~r27
		"\n"
		"	sha1msg1	%%xmm3, %%xmm6\n"
		"	pxor		%%xmm4, %%xmm6\n"
		"	sha1msg2	%%xmm5, %%xmm6\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm6, %%xmm2\n"
		"	sha1rnds4	$1, %%xmm2, %%xmm0\n"			// r28~r31
		"\n"
		"	sha1msg1	%%xmm4, %%xmm3\n"
		"	pxor		%%xmm5, %%xmm3\n"
		"	sha1msg2	%%xmm6, %%xmm3\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm3, %%xmm1\n"
		"	sha1rnds4	$1, %%xmm1, %%xmm0\n"			// r32~r35
		"\n"
		"	sha1msg1	%%xmm5, %%xmm4\n"
		"	pxor		%%xmm6, %%xmm4\n"
		"	sha1msg2	%%xmm3, %%xmm4\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm4, %%xmm2\n"
		"	sha1rnds4	$1, %%xmm2, %%xmm0\n"			// r36~r39
		"\n"
////////////////////
		"	sha1msg1	%%xmm6, %%xmm5\n"
		"	pxor		%%xmm3, %%xmm5\n"
		"	sha1msg2	%%xmm4, %%xmm5\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm5, %%xmm1\n"
		"	sha1rnds4	$2, %%xmm1, %%xmm0\n"			// r40~r43
		"\n"
		"	sha1msg1	%%xmm3, %%xmm6\n"
		"	pxor		%%xmm4, %%xmm6\n"
		"	sha1msg2	%%xmm5, %%xmm6\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm6, %%xmm2\n"
		"	sha1rnds4	$2, %%xmm2, %%xmm0\n"			// r44~r47
		"\n"
		"	sha1msg1	%%xmm4, %%xmm3\n"
		"	pxor		%%xmm5, %%xmm3\n"
		"	sha1msg2	%%xmm6, %%xmm3\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm3, %%xmm1\n"
		"	sha1rnds4	$2, %%xmm1, %%xmm0\n"			// r48~r51
		"\n"
		"	sha1msg1	%%xmm5, %%xmm4\n"
		"	pxor		%%xmm6, %%xmm4\n"
		"	sha1msg2	%%xmm3, %%xmm4\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm4, %%xmm2\n"
		"	sha1rnds4	$2, %%xmm2, %%xmm0\n"			// r52~r55
		"\n"
		"	sha1msg1	%%xmm6, %%xmm5\n"
		"	pxor		%%xmm3, %%xmm5\n"
		"	sha1msg2	%%xmm4, %%xmm5\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm5, %%xmm1\n"
		"	sha1rnds4	$2, %%xmm1, %%xmm0\n"			// r56~r59
		"\n"
////////////////////
		"	sha1msg1	%%xmm3, %%xmm6\n"
		"	pxor		%%xmm4, %%xmm6\n"
		"	sha1msg2	%%xmm5, %%xmm6\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm6, %%xmm2\n"
		"	sha1rnds4	$3, %%xmm2, %%xmm0\n"			// r60~r63
		"\n"
		"	sha1msg1	%%xmm4, %%xmm3\n"
		"	pxor		%%xmm5, %%xmm3\n"
		"	sha1msg2	%%xmm6, %%xmm3\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm3, %%xmm1\n"
		"	sha1rnds4	$3, %%xmm1, %%xmm0\n"			// r64~r67
		"\n"
		"	sha1msg1	%%xmm5, %%xmm4\n"
		"	pxor		%%xmm6, %%xmm4\n"
		"	sha1msg2	%%xmm3, %%xmm4\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm4, %%xmm2\n"
		"	sha1rnds4	$3, %%xmm2, %%xmm0\n"			// r68~r71
		"\n"
		"	sha1msg1	%%xmm6, %%xmm5\n"
		"	pxor		%%xmm3, %%xmm5\n"
		"	sha1msg2	%%xmm4, %%xmm5\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm2\n"				// abcd_save
		"	sha1nexte	%%xmm5, %%xmm1\n"
		"	sha1rnds4	$3, %%xmm1, %%xmm0\n"			// r72~r75
		"\n"
		"	sha1msg1	%%xmm3, %%xmm6\n"
		"	pxor		%%xmm4, %%xmm6\n"
		"	sha1msg2	%%xmm5, %%xmm6\n"
		"\n"
		"	movdqa		%%xmm0, %%xmm1\n"				// abcd_save
		"	sha1nexte	%%xmm6, %%xmm2\n"
		"	sha1rnds4	$3, %%xmm2, %%xmm0\n"			// r76~r79
		"\n"
		"	movdqu		(%0), %%xmm2\n"
		"	pshufd		$0b00011011, %%xmm0, %%xmm0\n"	// change word order
		"	paddd		%%xmm0, %%xmm2\n"
		"	movdqu		%%xmm2, (%0)\n"					// a, b, c, d
		"\n"
		"	pxor		%%xmm3, %%xmm3\n"
		"	sha1nexte	%%xmm3, %%xmm1\n"
		"\n"
		"	movd		16(%0), %%xmm2\n"
		"	pshufd		$0b00011011, %%xmm1, %%xmm1\n"	// change word order
		"	paddd		%%xmm1, %%xmm2\n"
		"	movd		%%xmm2, 16(%0)\n"				// e
		"\n"
		"	movdqa		(%[xmm_save]), %%xmm0\n"
		"	movdqa		0x10(%[xmm_save]), %%xmm1\n"
		"	movdqa		0x20(%[xmm_save]), %%xmm2\n"
		"	movdqa		0x30(%[xmm_save]), %%xmm3\n"
		"	movdqa		0x40(%[xmm_save]), %%xmm4\n"
		"	movdqa		0x50(%[xmm_save]), %%xmm5\n"
		"	movdqa		0x60(%[xmm_save]), %%xmm6\n"
		"	movdqa		0x70(%[xmm_save]), %%xmm7\n"
		:
		: "r" (ctx->h), [data] "r" (data), [order_byte] "m" (*order_byte), [xmm_save] "b" (xmm_save)
		: "memory");
}

void RaSha1CheckForInstructionSet( struct RaSha1Ctx *ctx )
{
	int a, b, c, d;

	// Look for CPUID.7.0.EBX[29]
	// EAX = 7, ECX = 0
	a = 7;
	c = 0;

	__asm__ volatile (
		"	cpuid"
		: "=a"( a ), "=b"( b ), "=c"( c ), "=d"( d )
		: "a"( a ), "c"( c )
		);
	// Intel SHA Extensions feature bit is EBX[29]
	if ( ( b >> 29 ) & 1 ) {
		ctx->fnRaSha1Process = RaSha1Process_x86;
	}
}

