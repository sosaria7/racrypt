/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <racrypt.h>

#define	UNROLL						1
#define RL(X, n)					((X << n) | (X >> (32 - n)))
#define CHANGE_ENDIAN(X)            (RL(X, 8) & 0x00ff00ff) | (RL(X,24) & 0xff00ff00)

static const int md4R[48] = {
	3,  7, 11, 19,  3,  7, 11, 19,  3,  7, 11, 19,  3,  7, 11, 19,
	3,  5,  9, 13,  3,  5,  9, 13,  3,  5,  9, 13,  3,  5,  9, 13,
	3,  9, 11, 15,  3,  9, 11, 15,  3,  9, 11, 15,  3,  9, 11, 15,
};

static const int md4W[48] = {
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	0,  4,  8, 12,  1,  5,  9, 13,  2,  6, 10, 14,  3,  7, 11, 15,
	0,  8,  4, 12,  2, 10,  6, 14,  1,  9,  5, 13,  3, 11,  7, 15
};

int RaMd4Create(struct RaMd4Ctx **ctxp)
{
	struct RaMd4Ctx *ctx;
	ctx = (struct RaMd4Ctx*)malloc(sizeof(struct RaMd4Ctx));
	if (ctx == NULL) {
		return BN_ERR_OUT_OF_MEMORY;
	}
	RaMd4Init(ctx);

	*ctxp = ctx;

	return BN_ERR_SUCCESS;
}

void RaMd4Destroy(struct RaMd4Ctx *ctx)
{
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(struct RaMd4Ctx));
		free(ctx);
	}
}

void RaMd4Init(struct RaMd4Ctx *ctx)
{
	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
}

#define GET_UINT32_LE(b)		(((b)[3] << 24)|((b)[2] << 16)|((b)[1] << 8)|(b)[0])
#define PUT_UINT32_LE(b, v)		{ (b)[3] = (v)>>24; (b)[2] = ((v)>>16) & 0xff; (b)[1] = ((v)>>8) & 0xff; (b)[0] = (v) & 0xff; }

#define R(n)						(md4R[n])
#define W(n)						(w[md4W[n]])

#define MD4_P(A, B, C, D, n)		{	\
	A = A + F(B, C, D) + K + W(n);	\
	A = RL(A, R(n));	\
	}

#define MD4_P_DO4(i)	{	\
	MD4_P(a, b, c, d, (i + 0));	\
	MD4_P(d, a, b, c, (i + 1));	\
	MD4_P(c, d, a, b, (i + 2));	\
	MD4_P(b, c, d, a, (i + 3));	\
}


static void RaMd4Process(struct RaMd4Ctx *ctx, const uint8_t data[64])
{
	uint32_t w[16];
	uint32_t a, b, c, d;
#ifndef UNROLL
    int i;
#endif

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];

	memcpy(w, data, 64);
#ifdef WORDS_BIGENDIAN
#ifndef UNROLL
    for (i = 0; i < 16; i++ )
        w[i] = CHANGE_ENDIAN(w[i]);
#else
    w[0] = CHANGE_ENDIAN(w[0]);
    w[1] = CHANGE_ENDIAN(w[1]);
    w[2] = CHANGE_ENDIAN(w[2]);
    w[3] = CHANGE_ENDIAN(w[3]);
    w[4] = CHANGE_ENDIAN(w[4]);
    w[5] = CHANGE_ENDIAN(w[5]);
    w[6] = CHANGE_ENDIAN(w[6]);
    w[7] = CHANGE_ENDIAN(w[7]);
    w[8] = CHANGE_ENDIAN(w[8]);
    w[9] = CHANGE_ENDIAN(w[9]);
    w[10] = CHANGE_ENDIAN(w[10]);
    w[11] = CHANGE_ENDIAN(w[11]);
    w[12] = CHANGE_ENDIAN(w[12]);
    w[13] = CHANGE_ENDIAN(w[13]);
    w[14] = CHANGE_ENDIAN(w[14]);
    w[15] = CHANGE_ENDIAN(w[15]);
#endif
#endif


#define F(B, C, D)				(D ^ (B & (C ^ D)))
#define K						0

#ifndef UNROLL
	for (i = 0; i < 16; i += 4) {
		MD4_P_DO4(i);
	}
#else
	MD4_P_DO4(0);
	MD4_P_DO4(4);
	MD4_P_DO4(8);
	MD4_P_DO4(12);
#endif

#undef F
#undef K
#define F(B, C, D)				((B & (C | D)) | (C & D))
#define K						0x5a827999

#ifndef UNROLL
	for (i = 16; i < 32; i += 4) {
		MD4_P_DO4(i);
	}
#else
	MD4_P_DO4(16);
	MD4_P_DO4(20);
	MD4_P_DO4(24);
	MD4_P_DO4(28);
#endif

#undef F
#undef K
#define F(B, C, D)				(B ^ C ^ D)
#define K						0x6ed9eba1

#ifndef UNROLL
	for (i = 32; i < 48; i += 4) {
		MD4_P_DO4(i);
	}
#else
	MD4_P_DO4(32);
	MD4_P_DO4(36);
    MD4_P_DO4(40);
    MD4_P_DO4(44);
#endif

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
}

void RaMd4Update(struct RaMd4Ctx *ctx, const uint8_t *data, int len)
{
	int bufferFilled;
	int bufferLeft;
	bufferFilled = ctx->totalLen_l & 0x3f;
	bufferLeft = 64 - bufferFilled;

	ctx->totalLen_l += len;
	if (ctx->totalLen_l < (uint32_t)len)
		ctx->totalLen_h++;

	if (bufferLeft < 64 && bufferLeft <= len) {
		memcpy(ctx->buffer + bufferFilled, data, bufferLeft);
		RaMd4Process(ctx, ctx->buffer);
		data += bufferLeft;
		len -= bufferLeft;
		bufferFilled = 0;
	}
	while (len >= 64) {
		RaMd4Process(ctx, data);
		data += 64;
		len -= 64;
	}
	if (len > 0)
		memcpy(ctx->buffer + bufferFilled, data, len);
}

void RaMd4Final(struct RaMd4Ctx *ctx, /*out*/uint8_t output[16])
{
	uint32_t val;

	int bufferFilled;
	int bufferLeft;

	// append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
	// append 0 <= k < 512 bits '0', such that the resulting message length in bits
	// is congruent to -64 === 448 (mod 512)
	// append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
	bufferFilled = ctx->totalLen_l & 0x3f;
	ctx->buffer[bufferFilled++] = 0x80;
	bufferLeft = 64 - bufferFilled;
	if (bufferLeft < 8) {
		memset(ctx->buffer + bufferFilled, 0, bufferLeft);
		RaMd4Process(ctx, ctx->buffer);
		bufferLeft = 64;
		bufferFilled = 0;
	}
	memset(ctx->buffer + bufferFilled, 0, bufferLeft - 8);

	val = (ctx->totalLen_l << 3);
	PUT_UINT32_LE(ctx->buffer + 64 - 8, val);

	val = (ctx->totalLen_h << 3) | (ctx->totalLen_l >> 29);
	PUT_UINT32_LE(ctx->buffer + 64 - 4, val);

	RaMd4Process(ctx, ctx->buffer);

	PUT_UINT32_LE(output, ctx->h[0]);
	PUT_UINT32_LE(output + 4, ctx->h[1]);
	PUT_UINT32_LE(output + 8, ctx->h[2]);
	PUT_UINT32_LE(output + 12, ctx->h[3]);
}

void RaMd4(const uint8_t *data, int len, /*out*/uint8_t output[16])
{
	struct RaMd4Ctx ctx;
	RaMd4Init(&ctx);
	RaMd4Update(&ctx, data, len);
	RaMd4Final(&ctx, output);
}
