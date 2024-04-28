#include <racrypt.h>

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

static void RaSha256Process_x86(struct RaSha2Ctx *ctx, const uint8_t data[64])
{
	const static uint8_t order_byte[] __attribute__((__aligned__(16))) = { 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c };
	uint8_t xmm_save[16 * 9];

	/*
	* xmm0: msg
	* xmm1: abef
	* xmm2: cdgh 
	* xmm3: temp 
	* xmm4: w3.w2.w1.w0
	* xmm5: w7.w6.w5.w4
	* xmm6: w11.w10.w9.w8
	* xmm7: w15.w14.w13.w12
	*/
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
		// Since ctx->h is a pointer to a 64-bit integer, the ABEF is assembled from the lower 32-bit values.
		"	movdqu		0x00(%0), %%xmm3\n"				// .b.a
		"	movdqu		0x20(%0), %%xmm1\n"				// .f.e
		"	pshufd		$0b01110010, %%xmm3, %%xmm3\n"	// ..ab
		"	pshufd		$0b01110010, %%xmm1, %%xmm1\n"	// ..ef
		"	punpcklqdq	%%xmm3, %%xmm1\n"				// abef
		"\n"
		"	movdqu		0x10(%0), %%xmm3\n"				// .d.c
		"	movdqu		0x30(%0), %%xmm2\n"				// .h.g
		"	pshufd		$0b01110010, %%xmm3, %%xmm3\n"	// ..cd
		"	pshufd		$0b01110010, %%xmm2, %%xmm2\n"	// ..gh
		"	punpcklqdq	%%xmm3, %%xmm2\n"				// cdgh
		"\n"
		//////////////////////////
		// SHA2_P(0~3)
		// read 1st 128bit message
		"	movdqu		0x00(%[data]), %%xmm0\n"		// w0...w3
		"	pshufb		%[order_byte], %%xmm0\n"		// w3.w2.w1.w0
		"	movdqa		%%xmm0, %%xmm4\n"
		// add four raSha256K values
		"	movdqu		0x00(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		// do sha256rnds2
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r0~r1, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w1.w0.w3.w2
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r2~r3, cdgh, abef
		"\n"
		//////////////////////////
		// SHA2_P(4~7)
		// read 2nd 128bit message
		"	movdqu		0x10(%[data]), %%xmm0\n"		// w4...w7
		"	pshufb		%[order_byte], %%xmm0\n"		// w7.w6.w5.w4
		"	movdqa		%%xmm0, %%xmm5\n"
		// add next four raSha256K values
		"	movdqu		0x10(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		// do sha256rnds2
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r4~r5, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w5.w4.w7.w6
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r6~r7, cdgh, abef
		"\n"
		//////////////////////////
		// SHA2_P(8~11)
		// read 3rd 128bit message
		"	movdqu		0x20(%[data]), %%xmm0\n"		// w8...w11
		"	pshufb		%[order_byte], %%xmm0\n"		// w11.w10.w9.w8
		"	movdqa		%%xmm0, %%xmm6\n"
		// add next four raSha256K values
		"	movdqu		0x20(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r8~r9, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w9.w8.w11.w10
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r10~r11, cdgh, abef
		"\n"
		//////////////////////////
		// SHA2_P(12~15)
		// read 4th 128bit message
		"	movdqu		0x30(%[data]), %%xmm0\n"		// w12...w15
		"	pshufb		%[order_byte], %%xmm0\n"			// w15.w14.w13.w12
		"	movdqa		%%xmm0, %%xmm7\n"
		// add next four raSha256K values
		"	movdqu		0x30(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r12~r13, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w13.w12.w15.w14
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r14~r15, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(16~19)
		"	sha256msg1	%%xmm5, %%xmm4\n"				// ...w4. : w3.w2.w1.w0
		"	movdqa		%%xmm7, %%xmm3\n"				// xmm3 = w15.w14.w13.w12
		"	palignr $4, %%xmm6, %%xmm3\n"				// xmm3 = w12.w11.w10.w9
		"	paddd		%%xmm3, %%xmm4\n"				// w12.w11.w10.w9 + w3.w2.w1.w0
		"	sha256msg2	%%xmm7, %%xmm4\n"				// w15.w14... : w3.w2.w1.w0
		"	movdqa		%%xmm4, %%xmm0\n"
		"\n"
		// SHA2_P(16~19)
		// add next four raSha256K values
		"	movdqu		0x40(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r16~r17, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w1.w0.w3.w2
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r18~r19, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(20~23)
		"	sha256msg1	%%xmm6, %%xmm5\n"				// ...w8. : w7.w6.w5.w4
		"	movdqa		%%xmm4, %%xmm3\n"				// xmm3 = w3.w2.w1.w0
		"	palignr $4, %%xmm7, %%xmm3\n"				// xmm3 = w0.w15.w14.w13
		"	paddd		%%xmm3, %%xmm5\n"				// w0.w15.w14.w13 + w7.w6.w5.w4
		"	sha256msg2	%%xmm4, %%xmm5\n"				// w3.w2... : w7.w6.w5.w4
		"	movdqa		%%xmm5, %%xmm0\n"
		"\n"
		// SHA2_P(20~23)
		// add next four raSha256K values
		"	movdqu		0x50(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r20~r21, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w5.w4.w7.w6
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r22~r23, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(24~27)
		"	sha256msg1	%%xmm7, %%xmm6\n"				// ...w12. : w11.w10.w9.w8
		"	movdqa		%%xmm5, %%xmm3\n"				// xmm3 = w7.w6.w5.w4
		"	palignr $4, %%xmm4, %%xmm3\n"				// xmm3 = w4.w3.w2.w1
		"	paddd		%%xmm3, %%xmm6\n"				// w4.w3.w2.w1 + w11.w10.w9.w8
		"	sha256msg2	%%xmm5, %%xmm6\n"				// w7.w6... : w11.w10.w9.w8
		"	movdqa		%%xmm6, %%xmm0\n"
		"\n"
		// SHA2_P(24~27)
		// add next four raSha256K values
		"	movdqu		0x60(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r24~r25, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w9.w8.w11.w10
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r26~r27, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(28~31)
		"	sha256msg1	%%xmm4, %%xmm7\n"				// ...w0. : w15.w14.w13.w12
		"	movdqa		%%xmm6, %%xmm3\n"				// xmm3 = w11.w10.w9.w8
		"	palignr $4, %%xmm5, %%xmm3\n"				// xmm3 = w8.w7.w6.w5
		"	paddd		%%xmm3, %%xmm7\n"				// w8.w7.w6.w5 + w15.w14.w13.w12
		"	sha256msg2	%%xmm6, %%xmm7\n"				// w11.w10... : w15.w14.w13.w12
		"	movdqa		%%xmm7, %%xmm0\n"
		"\n"
		// SHA2_P(28~31)
		// add next four raSha256K values
		"	movdqu		0x70(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r28~r29, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w13.w12.w15.w14
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r30~r31, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(32~35)
		"	sha256msg1	%%xmm5, %%xmm4\n"				// ...w4. : w3.w2.w1.w0
		"	movdqa		%%xmm7, %%xmm3\n"				// xmm3 = ...w12
		"	palignr $4, %%xmm6, %%xmm3\n"				// xmm3 = w12.w11.w10.w9
		"	paddd		%%xmm3, %%xmm4\n"				// w12.w11.w10.w9 + w3.w2.w1.w0
		"	sha256msg2	%%xmm7, %%xmm4\n"				// w15.w14... : w3.w2.w1.w0
		"	movdqa		%%xmm4, %%xmm0\n"
		"\n"
		// SHA2_P(32~35)
		// add next four raSha256K values
		"	movdqu		0x80(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r32~r33, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w1.w0.w3.w2
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r34~r35, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(36~39)
		"	sha256msg1	%%xmm6, %%xmm5\n"				// ...w8. : w7.w6.w5.w4
		"	movdqa		%%xmm4, %%xmm3\n"				// xmm3 = ...w0
		"	palignr $4, %%xmm7, %%xmm3\n"				// xmm3 = w0.w15.w14.w13
		"	paddd		%%xmm3, %%xmm5\n"				// w0.w15.w14.w13 + w7.w6.w5.w4
		"	sha256msg2	%%xmm4, %%xmm5\n"				// w3.w2... : w7.w6.w5.w4
		"	movdqa		%%xmm5, %%xmm0\n"
		"\n"
		// SHA2_P(36~39)
		// add next four raSha256K values
		"	movdqu		0x90(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r36~r37, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w5.w4.w7.w6
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r38~r39, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(40~43)
		"	sha256msg1	%%xmm7, %%xmm6\n"				// ...w12. : w11.w10.w9.w8
		"	movdqa		%%xmm5, %%xmm3\n"				// xmm3 = ...w4
		"	palignr $4, %%xmm4, %%xmm3\n"				// xmm3 = w4.w3.w2.w1
		"	paddd		%%xmm3, %%xmm6\n"				// w4.w3.w2.w1 + w11.w10.w9.w8
		"	sha256msg2	%%xmm5, %%xmm6\n"				// w7.w6... : w11.w10.w9.w8
		"	movdqa		%%xmm6, %%xmm0\n"
		"\n"
		// SHA2_P(40~43)
		// add next four raSha256K values
		"	movdqu		0xa0(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r40~r41, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w9.w8.w11.w10
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r42~r43, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(44~47)
		"	sha256msg1	%%xmm4, %%xmm7\n"				// ...w0. : w15.w14.w13.w12
		"	movdqa		%%xmm6, %%xmm3\n"				// xmm3 = ...w8
		"	palignr $4, %%xmm5, %%xmm3\n"				// xmm3 = w8.w7.w6.w5
		"	paddd		%%xmm3, %%xmm7\n"				// w8.w7.w6.w5 + w15.w14.w13.w12
		"	sha256msg2	%%xmm6, %%xmm7\n"				// w11.w10... : w15.w14.w13.w12
		"	movdqa		%%xmm7, %%xmm0\n"
		"\n"
		// SHA2_P(44~47)
		// add next four raSha256K values
		"	movdqu		0xb0(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r44~r45, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w13.w12.w15.w14
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r46~r47, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(48~51)
		"	sha256msg1	%%xmm5, %%xmm4\n"				// ...w4. : w3.w2.w1.w0
		"	movdqa		%%xmm7, %%xmm3\n"				// xmm3 = ...w12
		"	palignr $4, %%xmm6, %%xmm3\n"				// xmm3 = w12.w11.w10.w9
		"	paddd		%%xmm3, %%xmm4\n"				// w12.w11.w10.w9 + w3.w2.w1.w0
		"	sha256msg2	%%xmm7, %%xmm4\n"				// w15.w14... : w3.w2.w1.w0
		"	movdqa		%%xmm4, %%xmm0\n"
		"\n"
		// SHA2_P(48~51)
		// add next four raSha256K values
		"	movdqu		0xc0(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r48~r49, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w1.w0.w3.w2
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r50~r51, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(52~55)
		"	sha256msg1	%%xmm6, %%xmm5\n"				// ...w8. : w7.w6.w5.w4
		"	movdqa		%%xmm4, %%xmm3\n"				// xmm3 = ...w0
		"	palignr $4, %%xmm7, %%xmm3\n"				// xmm3 = w0.w15.w14.w13
		"	paddd		%%xmm3, %%xmm5\n"				// w0.w15.w14.w13 + w7.w6.w5.w4
		"	sha256msg2	%%xmm4, %%xmm5\n"				// w3.w2... : w7.w6.w5.w4
		"	movdqa		%%xmm5, %%xmm0\n"
		"\n"
		// SHA2_P(52~55)
		// add next four raSha256K values
		"	movdqu		0xd0(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r52~r53, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w5.w4.w7.w6
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r54~r55, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(56~59)
		"	sha256msg1	%%xmm7, %%xmm6\n"				// ...w12. : w11.w10.w9.w8
		"	movdqa		%%xmm5, %%xmm3\n"				// xmm3 = ...w4
		"	palignr $4, %%xmm4, %%xmm3\n"				// xmm3 = w4.w3.w2.w1
		"	paddd		%%xmm3, %%xmm6\n"				// w4.w3.w2.w1 + w11.w10.w9.w8
		"	sha256msg2	%%xmm5, %%xmm6\n"				// w7.w6... : w11.w10.w9.w8
		"	movdqa		%%xmm6, %%xmm0\n"
		"\n"
		// SHA2_P(56~59)
		// add next four raSha256K values
		"	movdqu		0xe0(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r56~r57, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w9.w8.w11.w10
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r58~r59, cdgh, abef
		"\n"
		/////////////////
		// SHA2_W(60~63)
		"	sha256msg1	%%xmm4, %%xmm7\n"				// ...w0. : w15.w14.w13.w12
		"	movdqa		%%xmm6, %%xmm3\n"				// xmm3 = ...w8
		"	palignr $4, %%xmm5, %%xmm3\n"				// xmm3 = w8.w7.w6.w5
		"	paddd		%%xmm3, %%xmm7\n"				// w8.w7.w6.w5 + w15.w14.w13.w12
		"	sha256msg2	%%xmm6, %%xmm7\n"				// w11.w10... : w15.w14.w13.w12
		"	movdqa		%%xmm7, %%xmm0\n"
		"\n"
		// SHA2_P(60~63)
		// add next four raSha256K values
		"	movdqu		0xf0(%[raSha256K]), %%xmm3\n"
		"	paddd		%%xmm3, %%xmm0\n"
		"	sha256rnds2	%%xmm1, %%xmm2\n"				// r60~r61, abef, cdgh
		"	pshufd		$0b01001110, %%xmm0, %%xmm0\n"	// w13.w12.w15.w14
		"	sha256rnds2	%%xmm2, %%xmm1\n"				// r62~r63, cdgh, abef
		"\n"
		/////////////////
		"	pxor %%xmm3, %%xmm3\n"
		"	pshufd		$0b00011011, %%xmm1, %%xmm0\n"	// xmm0 = feba
		"	punpckldq	%%xmm3, %%xmm0\n"				// .b.a
		"	movdqu		0x00(%0), %%xmm4\n"				// ctx[.b.a] += .b.a
		"	paddd		%%xmm0, %%xmm4\n"
		"	movdqu		%%xmm4, 0x00(%0)\n"
		"\n"
		"	pshufd		$0b10110001, %%xmm1, %%xmm0\n"	// xmm0 = bafe
		"	punpckldq	%%xmm3, %%xmm0\n"				// .f.e
		"	movdqu		0x20(%0), %%xmm4\n"				// ctx[.f.e] += .f.e
		"	paddd		%%xmm0, %%xmm4\n"
		"	movdqu		%%xmm4, 0x20(%0)\n"
		"\n"
		"	pshufd		$0b00011011, %%xmm2, %%xmm0\n"	// xmm0 = hgdc
		"	punpckldq	%%xmm3, %%xmm0\n"				// .d.c
		"	movdqu		0x10(%0), %%xmm4\n"				// ctx[.d.c] += .d.c
		"	paddd		%%xmm0, %%xmm4\n"
		"	movdqu		%%xmm4, 0x10(%0)\n"
		"\n"
		"	pshufd		$0b10110001, %%xmm2, %%xmm0\n"	// xmm0 = dchg
		"	punpckldq	%%xmm3, %%xmm0\n"				// .h.g
		"	movdqu		0x30(%0), %%xmm4\n"				// ctx[.h.g] += .h.g
		"	paddd		%%xmm0, %%xmm4\n"
		"	movdqu		%%xmm4, 0x30(%0)\n"
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
		: "r" (ctx->h), [data] "r" (data), [raSha256K] "r" (raSha256K), [order_byte] "m" (*order_byte), [xmm_save] "r" (xmm_save)
		: "memory");
}

void RaSha256CheckForInstructionSet( struct RaSha2Ctx *ctx )
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
		ctx->fnRaSha256Process = RaSha256Process_x86;
	}
}

