/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <string.h>
#include <stdlib.h>

#include "block_cipher.h"

static void RaAesEncryptBlock_x86(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
{
	struct RaAesCtx* ctx;
	uint8_t xmm_save[3 * 16] __attribute__((__aligned__(16)));

	ctx = CHILD_OF(blockCipher, struct RaAesCtx, blockCipher);

	__asm__ __volatile__ (
		"\n"
		"	add		$0x0c, %[xmm_save]\n"
		"	shr		$4, %[xmm_save]\n"
		"	shl		$4, %[xmm_save]\n"
		"	movdqa	%%xmm0, (%[xmm_save])\n"
		"	movdqa	%%xmm1, 0x10(%[xmm_save])\n"
		"\n"
		"	movdqu	%[input], %%xmm0\n"
		"\n"
		"	movdqu	0x00(%[key]), %%xmm1\n"
		"	pxor	%%xmm1, %%xmm0\n"
		"	movdqu	0x10(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0x20(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0x30(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0x40(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0x50(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0x60(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0x70(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0x80(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0x90(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	cmp		$11, %[nr]\n"
		"	jz		_end_enc_round\n"
		"	movdqu	0xa0(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0xb0(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	cmp		$13, %[nr]\n"
		"	jz		_end_enc_round\n"
		"	movdqu	0xc0(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"	movdqu	0xd0(%[key]), %%xmm1\n"
		"	aesenc	%%xmm1, %%xmm0\n"
		"_end_enc_round:\n"
		"	dec	%[nr]\n"
		"	shl	$4, %[nr]\n"
		"	movdqu	(%[key], %[nr], 1), %%xmm1\n"
		"	aesenclast %%xmm1, %%xmm0\n"
		"\n"
		"	movdqu	%%xmm0, %[output]\n"
		"\n"
		"	movdqa	(%[xmm_save]), %%xmm0\n"
		"	movdqa	0x10(%[xmm_save]), %%xmm1\n"
		:
		: [key] "r" ( ctx->key ), [nr] "r" ( (long)ctx->nr ), [input] "m" ( *input ),
		  [output] "m" ( *output ), [xmm_save] "r" ( xmm_save )
		: "memory" );
}

static void RaAesDecryptBlock_x86(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
{
	struct RaAesCtx *ctx;
	uint8_t xmm_save[2 * 16];

	ctx = CHILD_OF(blockCipher, struct RaAesCtx, blockCipher);

	__asm__ __volatile__ (
		"	push	%[nr]\n"
		"	add		$0x0c, %[xmm_save]\n"
		"	shr		$4, %[xmm_save]\n"
		"	shl		$4, %[xmm_save]\n"
		"	movdqa	%%xmm0, (%[xmm_save])\n"
		"	movdqa	%%xmm1, 0x10(%[xmm_save])\n"
		"\n"
		"	movdqu	%[input], %%xmm0\n"
		"\n"
		"	dec	%[nr]\n"
		"	shl	$4, %[nr]\n"
		"	movdqu	(%[key], %[nr], 1), %%xmm1\n"
		"	pxor	%%xmm1, %%xmm0\n"
		"\n"
		"	cmp		$0xc0, %[nr]\n"
		"	jz		_start_dec_round13\n"		// nr == 13
		"	jb		_start_dec_round11\n"		// nr == 11
		"\n"
		"	movdqu	0xd0(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0xc0(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"\n"
		"_start_dec_round13:\n"
		"	movdqu	0xb0(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0xa0(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"\n"
		"_start_dec_round11:\n"
		"	movdqu	0x90(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x80(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x70(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x60(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x50(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x40(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x30(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x20(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x10(%[rev_key]), %%xmm1\n"
		"	aesdec	%%xmm1, %%xmm0\n"
		"	movdqu	0x00(%[key]), %%xmm1\n"
		"	aesdeclast	%%xmm1, %%xmm0\n"
		"\n"
		"	movdqu	%%xmm0, %[output]\n"
		"\n"
		"	movdqa	(%[xmm_save]), %%xmm0\n"
		"	movdqa	0x10(%[xmm_save]), %%xmm1\n"
		"	pop		%[nr]"
		:
		: [key] "r" ( ctx->key ), [rev_key] "r" ( ctx->rev_key ), [nr] "r" ( (long)ctx->nr ),
		  [input] "m" ( *input ), [output] "m" ( *output ), [xmm_save] "r" ( xmm_save )
		: "memory" );
}

void RaAesCheckForIntelAesNI(struct RaBlockCipher* blockCipher)
{
	int a, b, c, d;

	// Look for CPUID.1.ECX[25]
	// EAX = 7, ECX = 0
	a = 1;

	__asm__ volatile (
		"	cpuid"
		: "=a"(a), "=b"(b), "=c"(c), "=d"(d)
		: "a"(a)
		);
	// AES-NI support
	if ((c >> 25) & 1) {
		blockCipher->encryptBlock = RaAesEncryptBlock_x86;
		blockCipher->decryptBlock = RaAesDecryptBlock_x86;
	}
}
