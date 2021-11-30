/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_DIGEST_H__
#define __RA_DIGEST_H__

#include "racrypt_com.h"

#ifdef __cplusplus
extern "C" {
#endif

enum RaDigestAlgorithm {
	RA_DGST_MD2,
	RA_DGST_MD4,
	RA_DGST_MD5,
	RA_DGST_SHA1,
	RA_DGST_SHA2_224,
	RA_DGST_SHA2_256,
	RA_DGST_SHA2_384,
	RA_DGST_SHA2_512,
	RA_DGST_SHA2_512_224,
	RA_DGST_SHA2_512_256
};

struct RaSha1Ctx
{
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint32_t h[5];
	uint8_t buffer[64];
};

int RaSha1Create(struct RaSha1Ctx **ctxp);
void RaSha1Destroy(struct RaSha1Ctx *ctx);
void RaSha1Init(struct RaSha1Ctx *ctx);
void RaSha1Update(struct RaSha1Ctx *ctx, const uint8_t *data, int len);
void RaSha1Final(struct RaSha1Ctx *ctx, /*out*/uint8_t data[20]);
void RaSha1(const uint8_t *data, int len, /*out*/uint8_t output[20]);

struct RaSha2Ctx
{
	uint64_t totalLen_hh;
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint64_t h[8];
	uint8_t buffer[128];
	enum RaDigestAlgorithm	algorithm;
};
#define RA_DGST_LEN_MD2				16
#define RA_DGST_LEN_MD4				16
#define RA_DGST_LEN_MD5				16
#define RA_DGST_LEN_SHA1			20
#define RA_DGST_LEN_SHA2_224		28
#define RA_DGST_LEN_SHA2_256		32
#define RA_DGST_LEN_SHA2_384		48
#define RA_DGST_LEN_SHA2_512		64
#define RA_DGST_LEN_SHA2_512_224	28
#define RA_DGST_LEN_SHA2_512_256	32

int RaSha2Create(enum RaDigestAlgorithm algorithm, struct RaSha2Ctx **ctxp);
void RaSha2Destroy(struct RaSha2Ctx *ctx);

void RaSha2Init(struct RaSha2Ctx *ctx, enum RaDigestAlgorithm algorithm);
void RaSha2Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);
void RaSha2Final(struct RaSha2Ctx *ctx, /*out*/uint8_t *output);

void RaSha256Init(struct RaSha2Ctx *ctx);
void RaSha256Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);
void RaSha256Final(struct RaSha2Ctx *ctx, /*out*/uint8_t data[32]);
void RaSha256(const uint8_t *data, int len, /*out*/uint8_t output[32]);

void RaSha512Init(struct RaSha2Ctx *ctx);
void RaSha512Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);
void RaSha512Final(struct RaSha2Ctx *ctx, /*out*/uint8_t data[64]);
void RaSha512(const uint8_t *data, int len, /*out*/uint8_t output[64]);

struct RaMd5Ctx
{
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint32_t h[4];
	uint8_t buffer[64];
};
int RaMd5Create(struct RaMd5Ctx **ctxp);
void RaMd5Destroy( struct RaMd5Ctx *ctx );
void RaMd5Init(struct RaMd5Ctx *ctx);
void RaMd5Update(struct RaMd5Ctx *ctx, const uint8_t *data, int len);
void RaMd5Final(struct RaMd5Ctx *ctx, /*out*/uint8_t data[16]);
void RaMd5(const uint8_t *data, int len, /*out*/uint8_t output[16]);

struct RaMd4Ctx
{
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint32_t h[4];
	uint8_t buffer[64];
};
int RaMd4Create(struct RaMd4Ctx **ctxp);
void RaMd4Destroy( struct RaMd4Ctx *ctx );
void RaMd4Init(struct RaMd4Ctx *ctx);
void RaMd4Update(struct RaMd4Ctx *ctx, const uint8_t *data, int len);
void RaMd4Final(struct RaMd4Ctx *ctx, /*out*/uint8_t data[16]);
void RaMd4(const uint8_t *data, int len, /*out*/uint8_t output[16]);

struct RaMd2Ctx
{
	uint32_t totalLen;
	uint8_t	state[16];
	uint8_t checksum[16];
	uint8_t buffer[16];
};
int RaMd2Create(struct RaMd2Ctx **ctxp);
void RaMd2Destroy( struct RaMd2Ctx *ctx );
void RaMd2Init(struct RaMd2Ctx *ctx);
void RaMd2Update(struct RaMd2Ctx *ctx, const uint8_t *data, int len);
void RaMd2Final(struct RaMd2Ctx *ctx, /*out*/uint8_t data[16]);
void RaMd2(const uint8_t *data, int len, /*out*/uint8_t output[16]);

struct RaHas160Ctx
{
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint32_t h[5];
	uint8_t buffer[64];
};

int RaHas160Create(struct RaHas160Ctx **ctxp);
void RaHas160Destroy(struct RaHas160Ctx *ctx);
void RaHas160Init(struct RaHas160Ctx *ctx);
void RaHas160Update(struct RaHas160Ctx *ctx, const uint8_t *data, int len);
void RaHas160Final(struct RaHas160Ctx *ctx, /*out*/uint8_t data[20]);
void RaHas160(const uint8_t *data, int len, /*out*/uint8_t output[20]);

#ifdef __cplusplus
}
#endif


#endif
