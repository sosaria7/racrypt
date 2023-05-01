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
	uint8_t xmm_save[16 * 8] __attribute__((__aligned__(16)));

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
		"movdqa %%xmm0, 0x00%4\n\t"
		"movdqa %%xmm1, 0x10%4\n\t"
		"movdqa %%xmm2, 0x20%4\n\t"
		"movdqa %%xmm3, 0x30%4\n\t"
		"movdqa %%xmm4, 0x40%4\n\t"
		"movdqa %%xmm5, 0x50%4\n\t"
		"movdqa %%xmm6, 0x60%4\n\t"
		"movdqa %%xmm7, 0x70%4\n\t"
		// h 에서 abef, cdgh 를 읽는다. h는 64bit이지만 하위 32bit만 사용한다.
		"movdqu 0x00(%0), %%xmm3\n\t"				// .b.a
		"movdqu 0x20(%0), %%xmm1\n\t"				// .f.e
		"pshufd $0b01110010, %%xmm3, %%xmm3\n\t"	// ..ab
		"pshufd $0b01110010, %%xmm1, %%xmm1\n\t"	// ..ef
		"punpcklqdq %%xmm3, %%xmm1\n\t"				// abef

		"movdqu 0x10(%0), %%xmm3\n\t"				// .d.c
		"movdqu 0x30(%0), %%xmm2\n\t"				// .h.g
		"pshufd $0b01110010, %%xmm3, %%xmm3\n\t"	// ..cd
		"pshufd $0b01110010, %%xmm2, %%xmm2\n\t"	// ..gh
		"punpcklqdq %%xmm3, %%xmm2\n\t"				// cdgh

		// msg 읽기
		"movdqu 0x00(%1), %%xmm0\n\t"				// w0...w3
		"pshufb %3, %%xmm0\n\t"						// w3.w2.w1.w0
		"movdqa %%xmm0, %%xmm4\n\t"
		// raSha256K 읽기
		"movdqu 0x00(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		/////////////////
		// msg 읽기
		"movdqu 0x10(%1), %%xmm0\n\t"				// w4...w7
		"pshufb %3, %%xmm0\n\t"						// w7.w6.w5.w4
		"movdqa %%xmm0, %%xmm5\n\t"
		// raSha256K 읽기
		"movdqu 0x10(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r4~r5, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w5.w4.w7.w6
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r6~r7, cdgh, abef

		/////////////////
		// msg 읽기
		"movdqu 0x20(%1), %%xmm0\n\t"				// w8...w11
		"pshufb %3, %%xmm0\n\t"						// w11.w10.w9.w8
		"movdqa %%xmm0, %%xmm6\n\t"
		// raSha256K 읽기
		"movdqu 0x20(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r8~r9, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w9.w8.w11.w10
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r10~r11, cdgh, abef

		/////////////////
		// msg 읽기
		"movdqu 0x30(%1), %%xmm0\n\t"				// w12...w15
		"pshufb %3, %%xmm0\n\t"						// w15.w14.w13.w12
		"movdqa %%xmm0, %%xmm7\n\t"
		// raSha256K 읽기
		"movdqu 0x30(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r12~r13, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w13.w12.w15.w14
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r14~r15, cdgh, abef

		/////////////////
		// SHA2_W(16~19)
		"sha256msg1 %%xmm5, %%xmm4\n\t"				// ...w4. : w3.w2.w1.w0
		"movdqa %%xmm7, %%xmm3\n\t"					// xmm3 = w15.w14.w13.w12
		"palignr $4, %%xmm6, %%xmm3\n\t"			// xmm3 = w12.w11.w10.w9
		"paddd %%xmm3, %%xmm4\n\t"					// w12.w11.w10.w9 + w3.w2.w1.w0
		"sha256msg2 %%xmm7, %%xmm4\n\t"				// w15.w14... : w3.w2.w1.w0
		"movdqa %%xmm4, %%xmm0\n\t"

		// SHA2_P(16~19)
		"movdqu 0x40(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r16~r17, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r18~r19, cdgh, abef

		/////////////////
		// SHA2_W(20~23)
		"sha256msg1 %%xmm6, %%xmm5\n\t"				// ...w8. : w7.w6.w5.w4
		"movdqa %%xmm4, %%xmm3\n\t"					// xmm3 = w3.w2.w1.w0
		"palignr $4, %%xmm7, %%xmm3\n\t"			// xmm3 = w0.w15.w14.w13
		"paddd %%xmm3, %%xmm5\n\t"					// w0.w15.w14.w13 + w7.w6.w5.w4
		"sha256msg2 %%xmm4, %%xmm5\n\t"				// w3.w2... : w7.w6.w5.w4
		"movdqa %%xmm5, %%xmm0\n\t"

		// SHA2_P(20~23)
		"movdqu 0x50(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r20~r21, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r22~r23, cdgh, abef

		/////////////////
		// SHA2_W(24~27)
		"sha256msg1 %%xmm7, %%xmm6\n\t"				// ...w12. : w11.w10.w9.w8
		"movdqa %%xmm5, %%xmm3\n\t"					// xmm3 = w7.w6.w5.w4
		"palignr $4, %%xmm4, %%xmm3\n\t"			// xmm3 = w4.w3.w2.w1
		"paddd %%xmm3, %%xmm6\n\t"					// w4.w3.w2.w1 + w11.w10.w9.w8
		"sha256msg2 %%xmm5, %%xmm6\n\t"				// w7.w6... : w11.w10.w9.w8
		"movdqa %%xmm6, %%xmm0\n\t"

		// SHA2_P(24~27)
		"movdqu 0x60(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r24~r25, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r26~r27, cdgh, abef

		/////////////////
		// SHA2_W(28~31)
		"sha256msg1 %%xmm4, %%xmm7\n\t"				// ...w0. : w15.w14.w13.w12
		"movdqa %%xmm6, %%xmm3\n\t"					// xmm3 = w11.w10.w9.w8
		"palignr $4, %%xmm5, %%xmm3\n\t"			// xmm3 = w8.w7.w6.w5
		"paddd %%xmm3, %%xmm7\n\t"					// w8.w7.w6.w5 + w15.w14.w13.w12
		"sha256msg2 %%xmm6, %%xmm7\n\t"				// w11.w10... : w15.w14.w13.w12
		"movdqa %%xmm7, %%xmm0\n\t"

		// SHA2_P(28~31)
		"movdqu 0x70(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r28~r29, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r30~r31, cdgh, abef

		/////////////////
		// SHA2_W(32~35)
		"sha256msg1 %%xmm5, %%xmm4\n\t"				// ...w4. : w3.w2.w1.w0
		"movdqa %%xmm7, %%xmm3\n\t"					// xmm3 = ...w12
		"palignr $4, %%xmm6, %%xmm3\n\t"			// xmm3 = w12.w11.w10.w9
		"paddd %%xmm3, %%xmm4\n\t"					// w12.w11.w10.w9 + w3.w2.w1.w0
		"sha256msg2 %%xmm7, %%xmm4\n\t"				// w15.w14... : w3.w2.w1.w0
		"movdqa %%xmm4, %%xmm0\n\t"

		// SHA2_P(32~35)
		"movdqu 0x80(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		/////////////////
		// SHA2_W(36~39)
		"sha256msg1 %%xmm6, %%xmm5\n\t"				// ...w8. : w7.w6.w5.w4
		"movdqa %%xmm4, %%xmm3\n\t"					// xmm3 = ...w0
		"palignr $4, %%xmm7, %%xmm3\n\t"			// xmm3 = w0.w15.w14.w13
		"paddd %%xmm3, %%xmm5\n\t"					// w0.w15.w14.w13 + w7.w6.w5.w4
		"sha256msg2 %%xmm4, %%xmm5\n\t"				// w3.w2... : w7.w6.w5.w4
		"movdqa %%xmm5, %%xmm0\n\t"

		// SHA2_P(36~39)
		"movdqu 0x90(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		/////////////////
		// SHA2_W(40~43)
		"sha256msg1 %%xmm7, %%xmm6\n\t"				// ...w12. : w11.w10.w9.w8
		"movdqa %%xmm5, %%xmm3\n\t"					// xmm3 = ...w4
		"palignr $4, %%xmm4, %%xmm3\n\t"			// xmm3 = w4.w3.w2.w1
		"paddd %%xmm3, %%xmm6\n\t"					// w4.w3.w2.w1 + w11.w10.w9.w8
		"sha256msg2 %%xmm5, %%xmm6\n\t"				// w7.w6... : w11.w10.w9.w8
		"movdqa %%xmm6, %%xmm0\n\t"

		// SHA2_P(40~43)
		"movdqu 0xa0(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		/////////////////
		// SHA2_W(44~47)
		"sha256msg1 %%xmm4, %%xmm7\n\t"				// ...w0. : w15.w14.w13.w12
		"movdqa %%xmm6, %%xmm3\n\t"					// xmm3 = ...w8
		"palignr $4, %%xmm5, %%xmm3\n\t"			// xmm3 = w8.w7.w6.w5
		"paddd %%xmm3, %%xmm7\n\t"					// w8.w7.w6.w5 + w15.w14.w13.w12
		"sha256msg2 %%xmm6, %%xmm7\n\t"				// w11.w10... : w15.w14.w13.w12
		"movdqa %%xmm7, %%xmm0\n\t"

		// SHA2_P(44~47)
		"movdqu 0xb0(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		/////////////////
		// SHA2_W(48~51)
		"sha256msg1 %%xmm5, %%xmm4\n\t"				// ...w4. : w3.w2.w1.w0
		"movdqa %%xmm7, %%xmm3\n\t"					// xmm3 = ...w12
		"palignr $4, %%xmm6, %%xmm3\n\t"			// xmm3 = w12.w11.w10.w9
		"paddd %%xmm3, %%xmm4\n\t"					// w12.w11.w10.w9 + w3.w2.w1.w0
		"sha256msg2 %%xmm7, %%xmm4\n\t"				// w15.w14... : w3.w2.w1.w0
		"movdqa %%xmm4, %%xmm0\n\t"

		// SHA2_P(48~51)
		"movdqu 0xc0(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		/////////////////
		// SHA2_W(52~55)
		"sha256msg1 %%xmm6, %%xmm5\n\t"				// ...w8. : w7.w6.w5.w4
		"movdqa %%xmm4, %%xmm3\n\t"					// xmm3 = ...w0
		"palignr $4, %%xmm7, %%xmm3\n\t"			// xmm3 = w0.w15.w14.w13
		"paddd %%xmm3, %%xmm5\n\t"					// w0.w15.w14.w13 + w7.w6.w5.w4
		"sha256msg2 %%xmm4, %%xmm5\n\t"				// w3.w2... : w7.w6.w5.w4
		"movdqa %%xmm5, %%xmm0\n\t"

		// SHA2_P(52~55)
		"movdqu 0xd0(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		/////////////////
		// SHA2_W(56~59)
		"sha256msg1 %%xmm7, %%xmm6\n\t"				// ...w12. : w11.w10.w9.w8
		"movdqa %%xmm5, %%xmm3\n\t"					// xmm3 = ...w4
		"palignr $4, %%xmm4, %%xmm3\n\t"			// xmm3 = w4.w3.w2.w1
		"paddd %%xmm3, %%xmm6\n\t"					// w4.w3.w2.w1 + w11.w10.w9.w8
		"sha256msg2 %%xmm5, %%xmm6\n\t"				// w7.w6... : w11.w10.w9.w8
		"movdqa %%xmm6, %%xmm0\n\t"

		// SHA2_P(56~59)
		"movdqu 0xe0(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		/////////////////
		// SHA2_W(60~63)
		"sha256msg1 %%xmm4, %%xmm7\n\t"				// ...w0. : w15.w14.w13.w12
		"movdqa %%xmm6, %%xmm3\n\t"					// xmm3 = ...w8
		"palignr $4, %%xmm5, %%xmm3\n\t"			// xmm3 = w8.w7.w6.w5
		"paddd %%xmm3, %%xmm7\n\t"					// w8.w7.w6.w5 + w15.w14.w13.w12
		"sha256msg2 %%xmm6, %%xmm7\n\t"				// w11.w10... : w15.w14.w13.w12
		"movdqa %%xmm7, %%xmm0\n\t"

		// SHA2_P(60~63)
		"movdqu 0xf0(%2), %%xmm3\n\t"
		"paddd %%xmm3, %%xmm0\n\t"
		"sha256rnds2 %%xmm1, %%xmm2\n\t"			// r0~r1, abef, cdgh
		"pshufd $0b01001110, %%xmm0, %%xmm0\n\t"	// w1.w0.w3.w2
		"sha256rnds2 %%xmm2, %%xmm1\n\t"			// r2~r3, cdgh, abef

		"pxor %%xmm3, %%xmm3\n\t"
		"pshufd $0b00011011, %%xmm1, %%xmm0\n\t"	// xmm0 = feba
		"punpckldq %%xmm3, %%xmm0\n\t"				// .b.a
		"movdqu 0x00(%0), %%xmm4\n\t"				// ctx[.b.a] += .b.a
		"paddd %%xmm0, %%xmm4\n\t"
		"movdqu %%xmm4, 0x00(%0)\n\t"

		"pshufd $0b10110001, %%xmm1, %%xmm0\n\t"	// xmm0 = bafe
		"punpckldq %%xmm3, %%xmm0\n\t"				// .f.e
		"movdqu 0x20(%0), %%xmm4\n\t"				// ctx[.f.e] += .f.e
		"paddd %%xmm0, %%xmm4\n\t"
		"movdqu %%xmm4, 0x20(%0)\n\t"

		"pshufd $0b00011011, %%xmm2, %%xmm0\n\t"	// xmm0 = hgdc
		"punpckldq %%xmm3, %%xmm0\n\t"				// .d.c
		"movdqu 0x10(%0), %%xmm4\n\t"				// ctx[.d.c] += .d.c
		"paddd %%xmm0, %%xmm4\n\t"
		"movdqu %%xmm4, 0x10(%0)\n\t"

		"pshufd $0b10110001, %%xmm2, %%xmm0\n\t"	// xmm0 = bafe
		"punpckldq %%xmm3, %%xmm0\n\t"				// .f.e
		"movdqu 0x30(%0), %%xmm4\n\t"				// ctx[.f.e] += .f.e
		"paddd %%xmm0, %%xmm4\n\t"
		"movdqu %%xmm4, 0x30(%0)\n\t"

		"movdqa 0x00%4, %%xmm0\n\t"
		"movdqa 0x10%4, %%xmm1\n\t"
		"movdqa 0x20%4, %%xmm2\n\t"
		"movdqa 0x30%4, %%xmm3\n\t"
		"movdqa 0x40%4, %%xmm4\n\t"
		"movdqa 0x50%4, %%xmm5\n\t"
		"movdqa 0x60%4, %%xmm6\n\t"
		"movdqa 0x70%4, %%xmm7\n\t"
		:
		: "r" (ctx->h), "r" (data), "r" (raSha256K), "m" (*order_byte), "m" (*xmm_save)
		: "memory");
}

void RaSha256CheckForIntelShaExtensions( struct RaSha2Ctx *ctx )
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
		ctx->fnRaSha256Process = RaSha256Process_x86;
	}
}

