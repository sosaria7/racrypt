/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <racrypt.h>

int RaSha2Create(struct RaSha2Ctx **ctxp)
{
	struct RaSha2Ctx *ctx;
	ctx = (struct RaSha2Ctx*)malloc(sizeof(struct RaSha2Ctx));
	if (ctx == NULL) {
		return BN_ERR_OUT_OF_MEMORY;
	}

	*ctxp = ctx;

	return BN_ERR_SUCCESS;
}

void RaSha2Destroy(struct RaSha2Ctx *ctx)
{
	if (ctx != NULL) {
		free(ctx);
	}
}

void RaSha256Init(struct RaSha2Ctx *ctx)
{
	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;
	ctx->h[0] = 0x6a09e667;
	ctx->h[1] = 0xbb67ae85;
	ctx->h[2] = 0x3c6ef372;
	ctx->h[3] = 0xa54ff53a;
	ctx->h[4] = 0x510e527f;
	ctx->h[5] = 0x9b05688c;
	ctx->h[6] = 0x1f83d9ab;
	ctx->h[7] = 0x5be0cd19;
	ctx->algorithm = RA_DGST_SHA2_256;
}

void RaSha224Init(struct RaSha2Ctx *ctx)
{
	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;
	ctx->h[0] = 0xc1059ed8;
	ctx->h[1] = 0x367cd507;
	ctx->h[2] = 0x3070dd17;
	ctx->h[3] = 0xf70e5939;
	ctx->h[4] = 0xffc00b31;
	ctx->h[5] = 0x68581511;
	ctx->h[6] = 0x64f98fa7;
	ctx->h[7] = 0xbefa4fa4;
	ctx->algorithm = RA_DGST_SHA2_224;
}

#define GET_UINT32_BE(b)		(uint32_t)(((b)[0] << 24)|((b)[1] << 16)|((b)[2] << 8)|(b)[3])
#define GET_UINT64_BE(b)		(((uint64_t)GET_UINT32_BE(b) << 32) | GET_UINT32_BE(b + 4))
#define PUT_UINT32_BE(b, v)		{ (b)[0] = ((v)>>24) & 0xff; (b)[1] = ((v)>>16) & 0xff; (b)[2] = ((v)>>8) & 0xff; (b)[3] = (v) & 0xff; }
#define PUT_UINT64_BE(b, v)		{ PUT_UINT32_BE(b, (v)>>32); PUT_UINT32_BE(b + 4, v); }

#define SHA2_CH(E, F, G)		(G ^ (E & (F ^ G)))
#define SHA2_MA(A, B, C)		((A & (B ^ C)) ^ (B & C))

#define SHA2_P1(A, B, C, D, E, F, G, H, n) {	\
	temp = SHA2_S1(E);	\
	temp += H + SHA2_CH(E, F, G) + SHA2_K(n) + w[(n) & 15];	\
	D += temp;	\
	temp += SHA2_S0(A);	\
	temp += SHA2_MA(A, B, C);	\
	H = temp;	\
	}

#define SHA2_W(n) {	\
	temp = w[(n - 15) & 15];	\
	w[(n) & 15] += SHA2_W0(temp);	\
	temp = w[(n - 2) & 15];	\
	w[(n) & 15] += w[(n - 7) & 15] + SHA2_W1(temp);	\
	}

#define SHA2_P12(A, B, C, D, E, F, G, H, n) {	\
	SHA2_W(n);	\
	SHA2_P1(A, B, C, D, E, F, G, H, n);	\
	}
#define SR(X, n)	(X >> n)

#define SHA2_P1_DO8(i) {	\
	SHA2_P1(a, b, c, d, e, f, g, h, (i + 0));	\
	SHA2_P1(h, a, b, c, d, e, f, g, (i + 1));	\
	SHA2_P1(g, h, a, b, c, d, e, f, (i + 2));	\
	SHA2_P1(f, g, h, a, b, c, d, e, (i + 3));	\
	SHA2_P1(e, f, g, h, a, b, c, d, (i + 4));	\
	SHA2_P1(d, e, f, g, h, a, b, c, (i + 5));	\
	SHA2_P1(c, d, e, f, g, h, a, b, (i + 6));	\
	SHA2_P1(b, c, d, e, f, g, h, a, (i + 7));	\
}
#define SHA2_P2_DO8(i) {	\
	SHA2_P12(a, b, c, d, e, f, g, h, (i + 0));	\
	SHA2_P12(h, a, b, c, d, e, f, g, (i + 1));	\
	SHA2_P12(g, h, a, b, c, d, e, f, (i + 2));	\
	SHA2_P12(f, g, h, a, b, c, d, e, (i + 3));	\
	SHA2_P12(e, f, g, h, a, b, c, d, (i + 4));	\
	SHA2_P12(d, e, f, g, h, a, b, c, (i + 5));	\
	SHA2_P12(c, d, e, f, g, h, a, b, (i + 6));	\
	SHA2_P12(b, c, d, e, f, g, h, a, (i + 7));	\
}

// sha256 defines
#define RR(X, n)	((X >> n) | (X << (32 - n)))
#define SHA2_W0(T)	(RR(T, 7) ^ RR(T, 18) ^ SR(T, 3))
#define SHA2_W1(T)	(RR(T, 17) ^ RR(T, 19) ^ SR(T, 10))
#define SHA2_S0(T)	(RR(T, 2) ^ RR(T, 13) ^ RR(T, 22))
#define SHA2_S1(T)	(RR(T, 6) ^ RR(T, 11) ^ RR(T, 25))
#define SHA2_K(n)	raSha256K[n]

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

static void RaSha256Process(struct RaSha2Ctx *ctx, const uint8_t data[64])
{
	uint32_t temp;
	uint32_t w[16];
	uint32_t a, b, c, d, e, f, g, h;
	int i;

	a = (uint32_t)ctx->h[0];
	b = (uint32_t)ctx->h[1];
	c = (uint32_t)ctx->h[2];
	d = (uint32_t)ctx->h[3];
	e = (uint32_t)ctx->h[4];
	f = (uint32_t)ctx->h[5];
	g = (uint32_t)ctx->h[6];
	h = (uint32_t)ctx->h[7];

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

	for (i = 0; i < 16; i += 8) {
		SHA2_P1_DO8(i);
	}

	for (i = 16; i < 64; i += 8) {
		SHA2_P2_DO8(i);
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

void RaSha256Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len)
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
		RaSha256Process(ctx, ctx->buffer);
		data += bufferLeft;
		len -= bufferLeft;
		bufferFilled = 0;
	}
	while (len >= 64) {
		RaSha256Process(ctx, data);
		data += 64;
		len -= 64;
	}
	if (len > 0)
		memcpy(ctx->buffer + bufferFilled, data, len);
}

void RaSha256Final(struct RaSha2Ctx *ctx, /*out*/uint8_t output[32])
{
	uint32_t val;

	int bufferFilled;
	int bufferLeft;

	// append a single '1' bit
	// append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
	// append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
	bufferFilled = ctx->totalLen_l & 0x3f;
	ctx->buffer[bufferFilled++] = 0x80;
	bufferLeft = 64 - bufferFilled;
	if (bufferLeft < 8) {
		memset(ctx->buffer + bufferFilled, 0, bufferLeft);
		RaSha256Process(ctx, ctx->buffer);
		bufferLeft = 64;
		bufferFilled = 0;
	}
	memset(ctx->buffer + bufferFilled, 0, bufferLeft - 8);

	val = (ctx->totalLen_h << 3) | (ctx->totalLen_l >> 29);
	PUT_UINT32_BE(ctx->buffer + 64 - 8, val);

	val = (ctx->totalLen_l << 3);
	PUT_UINT32_BE(ctx->buffer + 64 - 4, val);

	RaSha256Process(ctx, ctx->buffer);

	PUT_UINT32_BE(output, ctx->h[0]);
	PUT_UINT32_BE(output + 4, ctx->h[1]);
	PUT_UINT32_BE(output + 8, ctx->h[2]);
	PUT_UINT32_BE(output + 12, ctx->h[3]);
	PUT_UINT32_BE(output + 16, ctx->h[4]);
	PUT_UINT32_BE(output + 20, ctx->h[5]);
	PUT_UINT32_BE(output + 24, ctx->h[6]);
	if (ctx->algorithm != RA_DGST_LEN_SHA224) {
		PUT_UINT32_BE(output + 28, ctx->h[7]);
	}
}

void RaSha256(const uint8_t *data, int len, /*out*/uint8_t output[32])
{
	struct RaSha2Ctx ctx;
	RaSha256Init(&ctx);
	RaSha256Update(&ctx, data, len);
	RaSha256Final(&ctx, output);
}

#undef SHA2_W0
#undef SHA2_W1
#undef SHA2_S0
#undef SHA2_S1
#undef SHA2_K
#undef RR

// sha512 defines
#define RR(X, n)					((X >> n) | (X << (64 - n)))

#define SHA2_W0(T)	(RR(T, 1) ^ RR(T, 8) ^ SR(T, 7))
#define SHA2_W1(T)	(RR(T, 19) ^ RR(T, 61) ^ SR(T, 6))
#define SHA2_S0(T)	(RR(T, 28) ^ RR(T, 34) ^ RR(T, 39))
#define SHA2_S1(T)	(RR(T, 14) ^ RR(T, 18) ^ RR(T, 41))
#define SHA2_K(n)	raSha512K[n]

#define U64(d)		UINT64_C(d)

static const uint64_t raSha512K[80] = {
	U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd), U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc), U64(0x3956c25bf348b538),
	U64(0x59f111f1b605d019), U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118), U64(0xd807aa98a3030242), U64(0x12835b0145706fbe),
	U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2), U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1), U64(0x9bdc06a725c71235),
	U64(0xc19bf174cf692694), U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3), U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
	U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483), U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5), U64(0x983e5152ee66dfab),
	U64(0xa831c66d2db43210), U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4), U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725),
	U64(0x06ca6351e003826f), U64(0x142929670a0e6e70), U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926), U64(0x4d2c6dfc5ac42aed),
	U64(0x53380d139d95b3df), U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8), U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
	U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001), U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30), U64(0xd192e819d6ef5218),
	U64(0xd69906245565a910), U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8), U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53),
	U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8), U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb), U64(0x5b9cca4f7763e373),
	U64(0x682e6ff3d6b2b8a3), U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60), U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
	U64(0x90befffa23631e28), U64(0xa4506cebde82bde9), U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b), U64(0xca273eceea26619c),
	U64(0xd186b8c721c0c207), U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178), U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6),
	U64(0x113f9804bef90dae), U64(0x1b710b35131c471b), U64(0x28db77f523047d84), U64(0x32caab7b40c72493), U64(0x3c9ebe0a15c9bebc),
	U64(0x431d67c49c100d4c), U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a), U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817)
};

void RaSha512Init(struct RaSha2Ctx *ctx)
{
	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;
	ctx->h[0] = U64(0x6a09e667f3bcc908);
	ctx->h[1] = U64(0xbb67ae8584caa73b);
	ctx->h[2] = U64(0x3c6ef372fe94f82b);
	ctx->h[3] = U64(0xa54ff53a5f1d36f1);
	ctx->h[4] = U64(0x510e527fade682d1);
	ctx->h[5] = U64(0x9b05688c2b3e6c1f);
	ctx->h[6] = U64(0x1f83d9abfb41bd6b);
	ctx->h[7] = U64(0x5be0cd19137e2179);
	ctx->algorithm = RA_DGST_SHA2_512;
}

void RaSha384Init(struct RaSha2Ctx *ctx)
{
	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;
	ctx->h[0] = U64(0xcbbb9d5dc1059ed8);
	ctx->h[1] = U64(0x629a292a367cd507);
	ctx->h[2] = U64(0x9159015a3070dd17);
	ctx->h[3] = U64(0x152fecd8f70e5939);
	ctx->h[4] = U64(0x67332667ffc00b31);
	ctx->h[5] = U64(0x8eb44a8768581511);
	ctx->h[6] = U64(0xdb0c2e0d64f98fa7);
	ctx->h[7] = U64(0x47b5481dbefa4fa4);
	ctx->algorithm = RA_DGST_SHA2_384;
}

void RaSha512_224Init(struct RaSha2Ctx *ctx)
{
	/*
	// SHA-512/t IV Generation Function
	int i;
	uint8_t buffer[64];
	RaSha512Init(ctx);
	for (i = 0; i < 8; i++)
		ctx->h[i] ^= U64(0xa5a5a5a5a5a5a5a5);
	RaSha512Update(ctx, "SHA-512/224", 11);
	RaSha512Final(ctx, buffer);
	*/

	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;
	ctx->h[0] = U64(0x8c3d37c819544da2);
	ctx->h[1] = U64(0x73e1996689dcd4d6);
	ctx->h[2] = U64(0x1dfab7ae32ff9c82);
	ctx->h[3] = U64(0x679dd514582f9fcf);
	ctx->h[4] = U64(0x0f6d2b697bd44da8);
	ctx->h[5] = U64(0x77e36f7304c48942);
	ctx->h[6] = U64(0x3f9d85a86a1d36c8);
	ctx->h[7] = U64(0x1112e6ad91d692a1);
	ctx->algorithm = RA_DGST_SHA2_512_224;
}

void RaSha512_256Init(struct RaSha2Ctx *ctx)
{
	/*
	// SHA-512/t IV Generation Function
	int i;
	uint8_t buffer[64];
	RaSha512Init(ctx);
	for (i = 0; i < 8; i++)
		ctx->h[i] ^= U64(0xa5a5a5a5a5a5a5a5);
	RaSha512Update(ctx, "SHA-512/256", 11);
	RaSha512Final(ctx, buffer);
	*/
	ctx->totalLen_h = 0;
	ctx->totalLen_l = 0;

	ctx->h[0] = U64(0x22312194fc2bf72c);
	ctx->h[1] = U64(0x9f555fa3c84c64c2);
	ctx->h[2] = U64(0x2393b86b6f53b151);
	ctx->h[3] = U64(0x963877195940eabd);
	ctx->h[4] = U64(0x96283ee2a88effe3);
	ctx->h[5] = U64(0xbe5e1e2553863992);
	ctx->h[6] = U64(0x2b0199fc2c85b8aa);
	ctx->h[7] = U64(0x0eb72ddc81c52ca2);

	ctx->algorithm = RA_DGST_SHA2_512_256;
}

static void RaSha512Process(struct RaSha2Ctx *ctx, const uint8_t data[128])
{
	uint64_t temp;
	uint64_t w[16];
	uint64_t a, b, c, d, e, f, g, h;
	int i;

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	w[0] = GET_UINT64_BE(data);
	w[1] = GET_UINT64_BE(data + 8);
	w[2] = GET_UINT64_BE(data + 16);
	w[3] = GET_UINT64_BE(data + 24);
	w[4] = GET_UINT64_BE(data + 32);
	w[5] = GET_UINT64_BE(data + 40);
	w[6] = GET_UINT64_BE(data + 48);
	w[7] = GET_UINT64_BE(data + 56);
	w[8] = GET_UINT64_BE(data + 64);
	w[9] = GET_UINT64_BE(data + 72);
	w[10] = GET_UINT64_BE(data + 80);
	w[11] = GET_UINT64_BE(data + 88);
	w[12] = GET_UINT64_BE(data + 96);
	w[13] = GET_UINT64_BE(data + 104);
	w[14] = GET_UINT64_BE(data + 112);
	w[15] = GET_UINT64_BE(data + 120);


	for (i = 0; i < 16; i += 8) {
		SHA2_P1_DO8(i);
	}

	for (i = 16; i < 80; i += 8) {
		SHA2_P2_DO8(i);
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

void RaSha512Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len)
{
	int bufferFilled;
	int bufferLeft;
	bufferFilled = ctx->totalLen_l & 0x7f;
	bufferLeft = 128 - bufferFilled;

	ctx->totalLen_l += len;
	if (ctx->totalLen_l < (uint32_t)len)
		ctx->totalLen_h++;

	if (bufferLeft < 128 && bufferLeft <= len) {
		memcpy(ctx->buffer + bufferFilled, data, bufferLeft);
		RaSha512Process(ctx, ctx->buffer);
		data += bufferLeft;
		len -= bufferLeft;
		bufferFilled = 0;
	}
	while (len >= 128) {
		RaSha512Process(ctx, data);
		data += 128;
		len -= 128;
	}
	if (len > 0)
		memcpy(ctx->buffer + bufferFilled, data, len);
}

void RaSha512Final(struct RaSha2Ctx *ctx, /*out*/uint8_t output[64])
{
	uint32_t val;

	int bufferFilled;
	int bufferLeft;

	// append a single '1' bit
	// append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 1024
	// append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 1024 bits
	bufferFilled = ctx->totalLen_l & 0x7f;
	ctx->buffer[bufferFilled++] = 0x80;
	bufferLeft = 128 - bufferFilled;
	if (bufferLeft <= 8) {
		memset(ctx->buffer + bufferFilled, 0, bufferLeft);
		RaSha512Process(ctx, ctx->buffer);
		bufferLeft = 128;
		bufferFilled = 0;
	}
	memset(ctx->buffer + bufferFilled, 0, bufferLeft - 8);

	val = (ctx->totalLen_h << 3) | (ctx->totalLen_l >> 29);
	PUT_UINT32_BE(ctx->buffer + 128 - 8, val);

	val = (ctx->totalLen_l << 3);
	PUT_UINT32_BE(ctx->buffer + 128 - 4, val);

	RaSha512Process(ctx, ctx->buffer);

	PUT_UINT64_BE(output, ctx->h[0]);
	PUT_UINT64_BE(output + 8, ctx->h[1]);
	PUT_UINT64_BE(output + 16, ctx->h[2]);
	switch (ctx->algorithm)
	{
	case RA_DGST_SHA2_512:	default:
		PUT_UINT64_BE(output + 56, ctx->h[7]);
		PUT_UINT64_BE(output + 48, ctx->h[6]);
	case RA_DGST_SHA2_384:
		PUT_UINT64_BE(output + 40, ctx->h[5]);
		PUT_UINT64_BE(output + 32, ctx->h[4]);
	case RA_DGST_SHA2_512_256:
		PUT_UINT64_BE(output + 24, ctx->h[3]);
		break;
	case RA_DGST_SHA2_512_224:
		PUT_UINT32_BE(output + 24, ctx->h[3] >> 32);
		break;
	}
}

void RaSha512(const uint8_t *data, int len, /*out*/uint8_t output[64])
{
	struct RaSha2Ctx ctx;
	RaSha512Init(&ctx);
	RaSha512Update(&ctx, data, len);
	RaSha512Final(&ctx, output);
}

void RaSha2Init(struct RaSha2Ctx *ctx, enum RaDigestAlgorithm algorithm)
{
	switch (algorithm)
	{
	case RA_DGST_SHA2_224:
		RaSha224Init(ctx);
		break;
	case RA_DGST_SHA2_256:	default:
		RaSha256Init(ctx);
		break;
	case RA_DGST_SHA2_384:
		RaSha384Init(ctx);
		break;
	case RA_DGST_SHA2_512:
		RaSha512Init(ctx);
		break;
	case RA_DGST_SHA2_512_224:
		RaSha512_224Init(ctx);
		break;
	case RA_DGST_SHA2_512_256:
		RaSha512_256Init(ctx);
		break;
	}
}

void RaSha2Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len)
{
	switch (ctx->algorithm)
	{
	case RA_DGST_SHA2_224:
	case RA_DGST_SHA2_256:	default:
		RaSha256Update(ctx, data, len);
		break;
	case RA_DGST_SHA2_384:
	case RA_DGST_SHA2_512:
	case RA_DGST_SHA2_512_224:
	case RA_DGST_SHA2_512_256:
		RaSha512Update(ctx, data, len);
		break;
	}
}

void RaSha2Final(struct RaSha2Ctx *ctx, /*out*/uint8_t *output)
{
	switch (ctx->algorithm)
	{
	case RA_DGST_SHA2_224:
	case RA_DGST_SHA2_256:	default:
		RaSha256Final(ctx, output);
		break;
	case RA_DGST_SHA2_384:
	case RA_DGST_SHA2_512:
	case RA_DGST_SHA2_512_224:
	case RA_DGST_SHA2_512_256:
		RaSha512Final(ctx, output);
		break;
	}
}
