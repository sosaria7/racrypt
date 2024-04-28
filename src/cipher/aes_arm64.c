/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <string.h>
#include <stdlib.h>

#include "block_cipher.h"

static void RaAesEncryptBlock_arm64(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
{
	struct RaAesCtx* ctx;

	ctx = CHILD_OF(blockCipher, struct RaAesCtx, blockCipher);

	__asm__ __volatile__ (
		"\n"
		"	ld1		{v0.16b}, [%[input]]\n"

		// r1-r4
		"	ld1		{v1.16b, v2.16b, v3.16b, v4.16b}, [%[key]], #64\n"
		"	aese	v1.16b, v0.16b\n"
		"	aesmc	v0.16b, v1.16b\n"
		"	aese	v2.16b, v0.16b\n"
		"	aesmc	v0.16b, v2.16b\n"
		"	aese	v3.16b, v0.16b\n"
		"	aesmc	v0.16b, v3.16b\n"
		"	aese	v4.16b, v0.16b\n"
		"	aesmc	v0.16b, v4.16b\n"
		// r5-r7
		"	ld1		{v1.16b, v2.16b, v3.16b}, [%[key]], #48\n"
		"	aese	v1.16b, v0.16b\n"
		"	aesmc	v0.16b, v1.16b\n"
		"	aese	v2.16b, v0.16b\n"
		"	aesmc	v0.16b, v2.16b\n"
		"	aese	v3.16b, v0.16b\n"
		"	aesmc	v0.16b, v3.16b\n"
		// r8-r11
		"	ld1		{v1.16b, v2.16b, v3.16b, v4.16b}, [%[key]], #64\n"
		"	aese	v1.16b, v0.16b\n"
		"	aesmc	v0.16b, v1.16b\n"
		"	aese	v2.16b, v0.16b\n"
		"	aesmc	v0.16b, v2.16b\n"

        "   mov     v1.16b, v3.16b\n"
        "   mov     v2.16b, v4.16b\n"
		"	cmp		%[nr], #11\n"
		"	beq		_end_enc_round\n"

		"	aese	v1.16b, v0.16b\n"
		"	aesmc	v0.16b, v1.16b\n"
		"	aese	v2.16b, v0.16b\n"
		"	aesmc	v0.16b, v2.16b\n"

		// r12-r13
		"	ld1		{v1.16b, v2.16b, v3.16b, v4.16b}, [%[key]], #64\n"
		"	cmp		%[nr], #13\n"
		"	beq		_end_enc_round\n"

		"	aese	v1.16b, v0.16b\n"
		"	aesmc	v0.16b, v1.16b\n"

		"	aese	v2.16b, v0.16b\n"
		"	aesmc	v0.16b, v2.16b\n"

        "   mov     v1.16b, v3.16b\n"
        "   mov     v2.16b, v4.16b\n"
		// last-1, last
		"_end_enc_round:\n"
		"	aese	v0.16b, v1.16b\n"
		"	eor     v0.16b, v0.16b, v2.16b\n"
		"	st1		{v0.16b}, [%[output]]\n"
		:
		: [key] "r" ( ctx->key ), [nr] "r" ( (long)ctx->nr ),
		  [input] "r" ( input ), [output] "r" ( output )
		: "v0", "v1", "v2", "v3", "v4");
}

static void RaAesDecryptBlock_arm64(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
{
	struct RaAesCtx *ctx;

	ctx = CHILD_OF(blockCipher, struct RaAesCtx, blockCipher);

	// rev_shift row, rev_sub byte, add key, rev_mix col
	// (rev_shift_sub(input) + key) * rev_mix_col = (rev_shift_sub(input) * rev_mix_col) + (key * rev_mix_col)
	// = (rev_shift_sub(input) * rev_mix_col) + rev_key

	// v1 = aesd(input, key[nr-1])
	// v0 = aesimc(v1)
	// v1 = aesd(v0, rev_key[nr-2])
	// v0 = aesimc(v1)
	// v1 = aesd(v0, rev_key[nr-3])
	// ...
	// v0 = aesimc(v1)
	// v1 = aesd(v0, rev_key[1])
	// v0 ^= key[0]

	__asm__ __volatile__ (
		"	ld1		{v0.16b}, [%[input]]\n"

		"	add		x5, %[key], %[nr], lsl #4\n"
		"	sub		x5, x5, #16\n"
		"	ld1		{v1.16b}, [x5]\n"
		// v1 = aesd(input, key[nr-1])
		"	aesd	v1.16b, v0.16b\n"
		// v0 = aesimc(v1)
		"	aesimc	v0.16b, v1.16b\n"
		// v1 = aesd(v0, rev_key[nr-2])
		"	add		%[rev_key], %[rev_key], %[nr], lsl #4\n"
		"	sub		%[rev_key], %[rev_key], #64\n"
		"	ld1		{v1.16b, v2.16b, v3.16b}, [%[rev_key]]\n"
		"	aesd	v3.16b, v0.16b\n"
		"	aesimc	v0.16b, v3.16b\n"
		"	aesd	v2.16b, v0.16b\n"
		"	aesimc	v0.16b, v2.16b\n"
		"	aesd	v1.16b, v0.16b\n"
		"	aesimc	v0.16b, v1.16b\n"
		// (nr-5) ~ (nr-8)
		"	sub		%[rev_key], %[rev_key], #64\n"
		"	ld1		{v1.16b, v2.16b, v3.16b, v4.16b}, [%[rev_key]]\n"
		"	aesd	v4.16b, v0.16b\n"
		"	aesimc	v0.16b, v4.16b\n"
		"	aesd	v3.16b, v0.16b\n"
		"	aesimc	v0.16b, v3.16b\n"
		"	aesd	v2.16b, v0.16b\n"
		"	aesimc	v0.16b, v2.16b\n"
		"	aesd	v1.16b, v0.16b\n"
		"	aesimc	v0.16b, v1.16b\n"

		// (nr-9) ~ (nr-11)
		"	sub		%[rev_key], %[rev_key], #48\n"
		"	ld1		{v1.16b, v2.16b, v3.16b}, [%[rev_key]]\n"
		"	aesd	v3.16b, v0.16b\n"
		"	aesimc	v0.16b, v3.16b\n"

		"	cmp		%[nr], #11\n"
		"	beq		_end_dec_round\n"

		"	aesd	v2.16b, v0.16b\n"
		"	aesimc	v0.16b, v2.16b\n"
		"	aesd	v1.16b, v0.16b\n"
		"	aesimc	v0.16b, v1.16b\n"

		// (nr-12) ~ (nr-13)
		"	sub		%[rev_key], %[rev_key], #32\n"
		"	ld1		{v1.16b, v2.16b}, [%[rev_key]]\n"

		"	cmp		%[nr], #13\n"
		"	beq		_end_dec_round\n"

		"	aesd	v2.16b, v0.16b\n"
		"	aesimc	v0.16b, v2.16b\n"
		"	aesd	v1.16b, v0.16b\n"
		"	aesimc	v0.16b, v1.16b\n"

		// (nr-14)
		"	sub		%[rev_key], %[rev_key], #32\n"
		"	ld1		{v1.16b, v2.16b}, [%[rev_key]]\n"

		"_end_dec_round:\n"
		// v1 = aesd(v0, rev_key[1])
		"	aesd	v0.16b, v2.16b\n"

		// last round key addition
		"	ld1		{v1.16b}, [%[key]]\n"
		"	eor		v0.16b, v0.16b, v1.16b\n"
        "_end_dec_test:\n"
		"	st1		{v0.16b}, [%[output]]\n"

		:
		: [key] "r" ( ctx->key ), [rev_key] "r" ( ctx->rev_key ), [nr] "r" ( (long)ctx->nr ),
		  [input] "r" ( input ), [output] "r" ( output )
		: "x5", "v0", "v1", "v2", "v3", "v4" );
}

void RaAesCheckForInstructionSet(struct RaBlockCipher* blockCipher)
{
	int a;

    // https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/ID-AA64ISAR0-EL1--AArch64-Instruction-Set-Attribute-Register-0

    __asm__ __volatile__ (
        "   mrs     %0, ID_AA64ISAR0_EL1\n"
        : "=r" (a)
    );

    a = (a >> 4) & 0x0f;
	if (a == 1 || a == 2) {
		blockCipher->encryptBlock = RaAesEncryptBlock_arm64;
		blockCipher->decryptBlock = RaAesDecryptBlock_arm64;
	}
}

