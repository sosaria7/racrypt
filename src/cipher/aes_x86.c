/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <string.h>
#include <stdlib.h>

#include "block_cipher.h"

void RaAesEncryptBlock_x86(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
{
	struct RaAesCtx* ctx;
	uint8_t xmm_save[2 * 16] __attribute__((__aligned__(16)));

	ctx = CHILD_OF(blockCipher, struct RaAesCtx, blockCipher);

	__asm__ __volatile__ (
		"push %1\n\t"
		"movdqu %%xmm0, %4\n\t"
		"movdqu %%xmm1, 0x10 %4\n\t"

		"movdqu %2, %%xmm0\n\t"

		"movdqu 0x00(%0), %%xmm1\n\t"
		"pxor %%xmm1, %%xmm0\n\t"
		"movdqu 0x10(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0x20(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0x30(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0x40(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0x50(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0x60(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0x70(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0x80(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0x90(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"cmp $11, %1\n\t"
		"jz _end_enc_round\n\t"
		"movdqu 0xa0(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0xb0(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"cmp $13, %1\n\t"
		"jz _end_enc_round\n\t"
		"movdqu 0xc0(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"movdqu 0xd0(%0), %%xmm1\n\t"
		"aesenc %%xmm1, %%xmm0\n\t"
		"_end_enc_round:\n\t"
		"dec %1\n\t"
		"shl $4, %1\n\t"
		"movdqu (%0, %1, 1), %%xmm1\n\t"
		"aesenclast %%xmm1, %%xmm0\n\t"

		"movdqu %%xmm0, %3\n\t"

		"movdqu %4, %%xmm0\n\t"
		"movdqu 0x10 %4, %%xmm1\n\t"
		"pop %1"
		:
	: "r" ( ctx->key ), "r" ( (long)ctx->nr ), "m" ( *input ), "m" ( *output ), "m" ( *xmm_save )
		: "memory" );
}

void RaAesDecryptBlock_x86(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
{
	struct RaAesCtx *ctx;
	uint8_t xmm_save[2 * 16] __attribute__((__aligned__(16)));

	ctx = CHILD_OF(blockCipher, struct RaAesCtx, blockCipher);

	__asm__ __volatile__ (
		"push %2\n\t"
		"movdqu %%xmm0, %5\n\t"
		"movdqu %%xmm1, 0x10 %5\n\t"

		"movdqu %3, %%xmm0\n\t"

		"dec %2\n\t"
		"shl $4, %2\n\t"
		"movdqu (%0, %2, 1), %%xmm1\n"
		"pxor %%xmm1, %%xmm0\n"

		"cmp $0xc0, %2\n\t"
		"jz _start_dec_round13\n\t"		// nr == 13
		"jb _start_dec_round11\n\t"		// nr == 11

		"movdqu 0xd0(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n"
		"movdqu 0xc0(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"_start_dec_round13:\n\t"
		"movdqu 0xb0(%1), %%xmm1\n"
		"aesdec %%xmm1, %%xmm0\n"
		"movdqu 0xa0(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"_start_dec_round11:\n\t"
		"movdqu 0x90(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x80(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x70(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x60(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x50(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x40(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x30(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x20(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x10(%1), %%xmm1\n\t"
		"aesdec %%xmm1, %%xmm0\n\t"
		"movdqu 0x00(%0), %%xmm1\n\t"
		"aesdeclast %%xmm1, %%xmm0\n\t"

		"movdqu %%xmm0, %4\n\t"

		"movdqu %5, %%xmm0\n\t"
		"movdqu 0x10 %5, %%xmm1\n\t"
		"pop %2"

		:
	: "r" ( ctx->key ), "r" ( ctx->rev_key ), "r" ( (long)ctx->nr ), "m" ( *input ), "m" ( *output ), "m" ( *xmm_save )
		: "memory" );
}

void RaAesCheckForIntelAesNI(struct RaBlockCipher* blockCipher)
{
	int a, b, c, d;

	// Look for CPUID.7.0.EBX[29]
	// EAX = 7, ECX = 0
	a = 1;

	__asm__ volatile (
		"cpuid"
		: "=a"(a), "=b"(b), "=c"(c), "=d"(d)
		: "a"(a)
		);
	// AES-NI support
	if ((c >> 25) & 1) {
		blockCipher->encryptBlock = RaAesEncryptBlock_x86;
		blockCipher->decryptBlock = RaAesDecryptBlock_x86;
	}
}
