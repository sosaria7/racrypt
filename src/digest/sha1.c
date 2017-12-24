/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <racrypt.h>


int RaSha1Create(struct RaSha1Ctx **ctxp)
{
	struct RaSha1Ctx *ctx;
	ctx = (struct RaSha1Ctx*)malloc(sizeof(struct RaSha1Ctx));
	if (ctx == NULL) {
		return BN_ERR_OUT_OF_MEMORY;
	}
	RaSha1Init(ctx);

	*ctxp = ctx;

	return BN_ERR_SUCCESS;
}

void RaSha1Destroy(struct RaSha1Ctx *ctx)
{
	if (ctx != NULL) {
		free(ctx);
	}
}

void RaSha1Init(struct RaSha1Ctx *ctx)
{
	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xc3d2e1f0;
}

#define GET_UINT32_BE(b)		(((b)[0] << 24)|((b)[1] << 16)|((b)[2] << 8)|(b)[3])
#define PUT_UINT32_BE(b, v)		{ (b)[0] = (v)>>24; (b)[1] = ((v)>>16) & 0xff; (b)[2] = ((v)>>8) & 0xff; (b)[3] = (v) & 0xff; }

#define RL(X, n)					((X << n) | (X >> (32 - n)))
#define SHA1_P1(A, B, C, D, E, n)		{	\
	E = (RL(A,5) + F(B, C, D) + E + K + w[n & 15]);	\
	B = RL(B, 30);	\
	}
#define SHA1_P2(A, B, C, D, E, n)	{ \
	temp = w[(n - 3) & 15] ^ w[(n - 8) & 15] ^ w[(n - 14) & 15] ^ w[(n - 16) & 15];	\
	w[n & 15] = RL(temp, 1);	\
	SHA1_P1(A, B, C, D, E, n)	\
	}

#define SHA1_P1_DO5(i)	{	\
	SHA1_P1(a, b, c, d, e, (i + 0));	\
	SHA1_P1(e, a, b, c, d, (i + 1));	\
	SHA1_P1(d, e, a, b, c, (i + 2));	\
	SHA1_P1(c, d, e, a, b, (i + 3));	\
	SHA1_P1(b, c, d, e, a, (i + 4));	\
}

#define SHA1_P2_DO5(i)	{	\
	SHA1_P2(a, b, c, d, e, (i + 0));	\
	SHA1_P2(e, a, b, c, d, (i + 1));	\
	SHA1_P2(d, e, a, b, c, (i + 2));	\
	SHA1_P2(c, d, e, a, b, (i + 3));	\
	SHA1_P2(b, c, d, e, a, (i + 4));	\
}

static void RaSha1Process(struct RaSha1Ctx *ctx, const uint8_t data[64])
{
	uint32_t temp;
	uint32_t w[16];
	uint32_t a, b, c, d, e;
	int i;

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];

	w[0] = GET_UINT32_BE(data);
	w[1] = GET_UINT32_BE(data + 4);
	w[2] = GET_UINT32_BE(data + 8);
	w[3] = GET_UINT32_BE(data + 12);
	w[4] = GET_UINT32_BE(data + 16);
	w[5] = GET_UINT32_BE(data + 20);
	w[6] = GET_UINT32_BE(data + 24);
	w[7] = GET_UINT32_BE(data + 28);
	w[8] = GET_UINT32_BE(data + 32);
	w[9] = GET_UINT32_BE(data + 36);
	w[10] = GET_UINT32_BE(data + 40);
	w[11] = GET_UINT32_BE(data + 44);
	w[12] = GET_UINT32_BE(data + 48);
	w[13] = GET_UINT32_BE(data + 52);
	w[14] = GET_UINT32_BE(data + 56);
	w[15] = GET_UINT32_BE(data + 60);


//#define F(B, C, D)				((B & C) | (~B & D))
#define F(B, C, D)				(D ^ (B & (C ^ D)))
#define K						0x5a827999
	
	for (i = 0; i < 15; i += 5) {
		SHA1_P1_DO5(i);
	}

	SHA1_P1(a, b, c, d, e, 15);
	SHA1_P2(e, a, b, c, d, 16);
	SHA1_P2(d, e, a, b, c, 17);
	SHA1_P2(c, d, e, a, b, 18);
	SHA1_P2(b, c, d, e, a, 19);

#undef F
#undef K
#define F(B, C, D)				(B ^ C ^ D)
#define K						0x6ed9eba1

	for (i = 20; i < 40; i += 5) {
		SHA1_P2_DO5(i);
	}

#undef F
#undef K
//#define F(B, C, D)				((B & C) | (C & D) | (D & B))
#define F(B, C, D)				((B & (C | D)) | (C & D))
#define K						0x8f1bbcdc

	for (i = 40; i < 60; i += 5) {
		SHA1_P2_DO5(i);
	}

#undef F
#undef K
#define F(B, C, D)				(B ^ C ^ D)
#define K						0xca62c1d6

	for (i = 60; i < 80; i += 5) {
		SHA1_P2_DO5(i);
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;

}

void RaSha1Update(struct RaSha1Ctx *ctx, const uint8_t *data, int len)
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
		RaSha1Process(ctx, ctx->buffer);
		data += bufferLeft;
		len -= bufferLeft;
		bufferFilled = 0;
	}
	while (len >= 64) {
		RaSha1Process(ctx, data);
		data += 64;
		len -= 64;
	}
	if (len > 0)
		memcpy(ctx->buffer + bufferFilled, data, len);
}

void RaSha1Final(struct RaSha1Ctx *ctx, /*out*/uint8_t output[20])
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
	if (bufferLeft <= 8) {
		memset(ctx->buffer + bufferFilled, 0, bufferLeft);
		RaSha1Process(ctx, ctx->buffer);
		bufferLeft = 64;
		bufferFilled = 0;
	}
	memset(ctx->buffer + bufferFilled, 0, bufferLeft - 8);

	val = (ctx->totalLen_h << 3) | (ctx->totalLen_l >> 29);
	PUT_UINT32_BE(ctx->buffer + 64 - 8, val);

	val = (ctx->totalLen_l << 3);
	PUT_UINT32_BE(ctx->buffer + 64 - 4, val);

	RaSha1Process(ctx, ctx->buffer);

	PUT_UINT32_BE(output, ctx->h[0]);
	PUT_UINT32_BE(output + 4, ctx->h[1]);
	PUT_UINT32_BE(output + 8, ctx->h[2]);
	PUT_UINT32_BE(output + 12, ctx->h[3]);
	PUT_UINT32_BE(output + 16, ctx->h[4]);
}

void RaSha1(const uint8_t *data, int len, /*out*/uint8_t output[20])
{
	struct RaSha1Ctx ctx;
	RaSha1Init(&ctx);
	RaSha1Update(&ctx, data, len);
	RaSha1Final(&ctx, output);
}
