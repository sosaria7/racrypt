/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define RL(X, n)					((X << n) | (X >> (32 - n)))
#define CHANGE_ENDIAN(X)            (RL(X, 8) & 0x00ff00ff) | (RL(X,24) & 0xff00ff00)

static const int has160R[80] = {
	 5, 11,  7, 15,  6, 13,  8, 14,  7, 12,  9, 11,  8, 15,  6, 12,  9, 14,  5, 13,
	 5, 11,  7, 15,  6, 13,  8, 14,  7, 12,  9, 11,  8, 15,  6, 12,  9, 14,  5, 13,
	 5, 11,  7, 15,  6, 13,  8, 14,  7, 12,  9, 11,  8, 15,  6, 12,  9, 14,  5, 13,
	 5, 11,  7, 15,  6, 13,  8, 14,  7, 12,  9, 11,  8, 15,  6, 12,  9, 14,  5, 13
};

int RaHas160Create(struct RaHas160Ctx **ctxp)
{
	struct RaHas160Ctx *ctx;
	ctx = (struct RaHas160Ctx*)malloc(sizeof(struct RaHas160Ctx));
	if (ctx == NULL) {
		return RA_ERR_OUT_OF_MEMORY;
	}
	RaHas160Init(ctx);

	*ctxp = ctx;

	return RA_ERR_SUCCESS;
}

void RaHas160Destroy(struct RaHas160Ctx *ctx)
{
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(struct RaHas160Ctx));
		free(ctx);
	}
}

void RaHas160Init(struct RaHas160Ctx *ctx)
{
	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xc3d2e1f0;
}

#define GET_UINT32_LE(b)		(((b)[3] << 24)|((b)[2] << 16)|((b)[1] << 8)|(b)[0])
#define PUT_UINT32_LE(b, v)		{ (b)[3] = (uint8_t)((v)>>24); (b)[2] = (uint8_t)((v)>>16); (b)[1] = (uint8_t)((v)>>8); (b)[0] = (uint8_t)(v); }

#define HAS160_F1(B, C, D)			(D ^ (B & (C ^ D)))
#define HAS160_F2(B, C, D)			(B ^ C ^ D)
#define HAS160_F3(B, C, D)			(C ^ (B | ~D))
#define HAS160_F4(B, C, D)			HAS160_F2(B, C, D)
#define HAS160_R1					10
#define HAS160_R2					17
#define HAS160_R3					25
#define HAS160_R4					30
#define HAS160_S1					1
#define HAS160_S2					3
#define HAS160_S3					9
#define HAS160_S4					11
#define HAS160_K1					0x00000000
#define HAS160_K2					0x5a827999
#define HAS160_K3					0x6ed9eba1
#define HAS160_K4					0x8f1bbcdc

#define HAS160_P(A, B, C, D, E, X, n)		{	\
	E += (RL(A, has160R[n]) + F(B, C, D) + K + X);	\
	B = RL(B, R);	\
	}
#define HAS160_P_DO5(x, n)		{	\
	temp = w[(x + S * 0) % 16] ^	\
		   w[(x + S * 1) % 16] ^	\
		   w[(x + S * 2) % 16] ^	\
		   w[(x + S * 3) % 16];		\
	HAS160_P(a, b, c, d, e, temp, n)	\
	HAS160_P(e, a, b, c, d, w[(x + S * 8) % 16], (n + 1))	\
	HAS160_P(d, e, a, b, c, w[(x + S * 9) % 16], (n + 2))	\
	HAS160_P(c, d, e, a, b, w[(x + S * 10) % 16], (n + 3))	\
	HAS160_P(b, c, d, e, a, w[(x + S * 11) % 16], (n + 4))	\
}

static void RaHas160Process(struct RaHas160Ctx *ctx, const uint8_t data[64])
{
	uint32_t temp;
	uint32_t w[16];
	uint32_t a, b, c, d, e;

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];

	memcpy(w, data, 64);
#ifdef WORDS_BIGENDIAN
#ifndef RACRYPT_DIGEST_UNROLL
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

#define F			HAS160_F1
#define K			HAS160_K1
#define R			HAS160_R1
#define S			HAS160_S1
	HAS160_P_DO5( 8,  0);
	HAS160_P_DO5(12,  5);
	HAS160_P_DO5( 0, 10);
	HAS160_P_DO5( 4, 15);

#undef	F
#undef	K
#undef	R
#undef	S
#define F			HAS160_F2
#define K			HAS160_K2
#define R			HAS160_R2
#define S			HAS160_S2
	HAS160_P_DO5(11, 20);
	HAS160_P_DO5( 7, 25);
	HAS160_P_DO5( 3, 30);
	HAS160_P_DO5(15, 35);

#undef	F
#undef	K
#undef	R
#undef	S
#define F			HAS160_F3
#define K			HAS160_K3
#define R			HAS160_R3
#define S			HAS160_S3
	HAS160_P_DO5( 4, 40);
	HAS160_P_DO5( 8, 45);
	HAS160_P_DO5(12, 50);
	HAS160_P_DO5( 0, 55);

#undef	F
#undef	K
#undef	R
#undef	S
#define F			HAS160_F4
#define K			HAS160_K4
#define R			HAS160_R4
#define S			HAS160_S4
	HAS160_P_DO5(15, 60);
	HAS160_P_DO5(11, 65);
	HAS160_P_DO5( 7, 70);
	HAS160_P_DO5( 3, 75);
#undef	F
#undef	K
#undef	R
#undef	S

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;

}

void RaHas160Update(struct RaHas160Ctx *ctx, const uint8_t *data, int len)
{
	int bufferFilled;
	int bufferRemain;
	bufferFilled = ctx->totalLen_l & 0x3f;
	bufferRemain = 64 - bufferFilled;

	ctx->totalLen_l += len;
	if (ctx->totalLen_l < (uint32_t)len)
		ctx->totalLen_h++;

	if (bufferRemain < 64 && bufferRemain <= len) {
		memcpy(ctx->buffer + bufferFilled, data, bufferRemain);
		RaHas160Process(ctx, ctx->buffer);
		data += bufferRemain;
		len -= bufferRemain;
		bufferFilled = 0;
	}
	while (len >= 64) {
		RaHas160Process(ctx, data);
		data += 64;
		len -= 64;
	}
	if (len > 0)
		memcpy(ctx->buffer + bufferFilled, data, len);
}

void RaHas160Final(struct RaHas160Ctx *ctx, /*out*/uint8_t output[20])
{
	uint32_t val;

	int bufferFilled;
	int bufferRemain;

	bufferFilled = ctx->totalLen_l & 0x3f;
	ctx->buffer[bufferFilled++] = 0x80;
	bufferRemain = 64 - bufferFilled;
	if (bufferRemain < 8) {
		memset(ctx->buffer + bufferFilled, 0, bufferRemain);
		RaHas160Process(ctx, ctx->buffer);
		bufferRemain = 64;
		bufferFilled = 0;
	}
	memset(ctx->buffer + bufferFilled, 0, bufferRemain - 8);

	val = (ctx->totalLen_l << 3);
	PUT_UINT32_LE(ctx->buffer + 64 - 8, val);

	val = (ctx->totalLen_h << 3) | (ctx->totalLen_l >> 29);
	PUT_UINT32_LE(ctx->buffer + 64 - 4, val);

	RaHas160Process(ctx, ctx->buffer);

	PUT_UINT32_LE(output, ctx->h[0]);
	PUT_UINT32_LE(output + 4, ctx->h[1]);
	PUT_UINT32_LE(output + 8, ctx->h[2]);
	PUT_UINT32_LE(output + 12, ctx->h[3]);
	PUT_UINT32_LE(output + 16, ctx->h[4]);
}

void RaHas160(const uint8_t *data, int len, /*out*/uint8_t output[20])
{
	struct RaHas160Ctx ctx;
	RaHas160Init(&ctx);
	RaHas160Update(&ctx, data, len);
	RaHas160Final(&ctx, output);
}
