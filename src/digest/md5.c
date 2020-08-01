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

static const int md5R[64] = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

static const uint32_t md5K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

int RaMd5Create(struct RaMd5Ctx **ctxp)
{
	struct RaMd5Ctx *ctx;
	ctx = (struct RaMd5Ctx*)malloc(sizeof(struct RaMd5Ctx));
	if (ctx == NULL) {
		return BN_ERR_OUT_OF_MEMORY;
	}
	RaMd5Init(ctx);

	*ctxp = ctx;

	return BN_ERR_SUCCESS;
}

void RaMd5Destroy(struct RaMd5Ctx *ctx)
{
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(struct RaMd5Ctx));
		free(ctx);
	}
}

void RaMd5Init(struct RaMd5Ctx *ctx)
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

#define K(n)						(md5K[n])
#define R(n)						(md5R[n])

#define MD5_P(A, B, C, D, n)		{	\
	A = A + F(B, C, D) + K(n) + W(n);	\
	A = B + RL(A, R(n));	\
	}

#define MD5_P_DO4(i)	{	\
	MD5_P(a, b, c, d, (i + 0));	\
	MD5_P(d, a, b, c, (i + 1));	\
	MD5_P(c, d, a, b, (i + 2));	\
	MD5_P(b, c, d, a, (i + 3));	\
}

static void RaMd5Process(struct RaMd5Ctx *ctx, const uint8_t data[64])
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
#define W(n)					(w[n])

#ifndef UNROLL
	for (i = 0; i < 16; i += 4) {
		MD5_P_DO4(i);
	}
#else
    MD5_P_DO4(0);
    MD5_P_DO4(4);
    MD5_P_DO4(8);
    MD5_P_DO4(12);
#endif

#undef F
#undef W
#define F(B, C, D)				(C ^ (D & (B ^ C)))
#define W(n)					(w[(5 * n + 1) % 16])

#ifndef UNROLL
	for (i = 16; i < 32; i += 4) {
		MD5_P_DO4(i);
	}
#else
    MD5_P_DO4(16);
    MD5_P_DO4(20);
    MD5_P_DO4(24);
    MD5_P_DO4(28);
#endif

#undef F
#undef W
#define F(B, C, D)				(B ^ C ^ D)
#define W(n)					(w[(3 * n + 5) % 16])

#ifndef UNROLL
	for (i = 32; i < 48; i += 4) {
		MD5_P_DO4(i);
	}
#else
    MD5_P_DO4(32);
    MD5_P_DO4(36);
    MD5_P_DO4(40);
    MD5_P_DO4(44);
#endif

#undef F
#undef W
#define F(B, C, D)				(C ^ (B | (~D)))
#define W(n)					(w[(7 * n) % 16])

#ifndef UNROLL
	for (i = 48; i < 64; i += 4) {
		MD5_P_DO4(i);
	}
#else
    MD5_P_DO4(48);
    MD5_P_DO4(52);
    MD5_P_DO4(56);
    MD5_P_DO4(60);
#endif

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
}

void RaMd5Update(struct RaMd5Ctx *ctx, const uint8_t *data, int len)
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
		RaMd5Process(ctx, ctx->buffer);
		data += bufferLeft;
		len -= bufferLeft;
		bufferFilled = 0;
	}
	while (len >= 64) {
		RaMd5Process(ctx, data);
		data += 64;
		len -= 64;
	}
	if (len > 0)
		memcpy(ctx->buffer + bufferFilled, data, len);
}

void RaMd5Final(struct RaMd5Ctx *ctx, /*out*/uint8_t output[16])
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
		RaMd5Process(ctx, ctx->buffer);
		bufferLeft = 64;
		bufferFilled = 0;
	}
	memset(ctx->buffer + bufferFilled, 0, bufferLeft - 8);

	val = (ctx->totalLen_l << 3);
	PUT_UINT32_LE(ctx->buffer + 64 - 8, val);

	val = (ctx->totalLen_h << 3) | (ctx->totalLen_l >> 29);
	PUT_UINT32_LE(ctx->buffer + 64 - 4, val);

	RaMd5Process(ctx, ctx->buffer);

	PUT_UINT32_LE(output, ctx->h[0]);
	PUT_UINT32_LE(output + 4, ctx->h[1]);
	PUT_UINT32_LE(output + 8, ctx->h[2]);
	PUT_UINT32_LE(output + 12, ctx->h[3]);
}

void RaMd5(const uint8_t *data, int len, /*out*/uint8_t output[16])
{
	struct RaMd5Ctx ctx;
	RaMd5Init(&ctx);
	RaMd5Update(&ctx, data, len);
	RaMd5Final(&ctx, output);
}
