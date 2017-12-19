/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#pragma once
#ifndef __RA_DIGEST_H__
#define __RA_DIGEST_H__

#include "racrypt_com.h"

#ifdef __cplusplus
extern "C" {
#endif

enum RaDigestAlgorithm {
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
void RaSha1Finish(struct RaSha1Ctx *ctx, /*out*/uint8_t data[20]);
void RaSha1(const uint8_t *data, int len, /*out*/uint8_t output[20]);

struct RaSha2Ctx
{
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint64_t h[8];
	uint8_t buffer[128];
	enum RaDigestAlgorithm	algorithm;
};
#define RA_DGST_LEN_SHA1		20
#define RA_DGST_LEN_SHA224		28
#define RA_DGST_LEN_SHA256		32
#define RA_DGST_LEN_SHA384		48
#define RA_DGST_LEN_SHA512		64
#define RA_DGST_LEN_SHA512_224	28
#define RA_DGST_LEN_SHA512_256	32

int RaSha2Create(struct RaSha2Ctx **ctxp);
void RaSha2Destroy(struct RaSha2Ctx *ctx);

void RaSha2Init(struct RaSha2Ctx *ctx, enum RaDigestAlgorithm algorithm);
void RaSha2Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);
void RaSha2Finish(struct RaSha2Ctx *ctx, /*out*/uint8_t *output);

void RaSha256Init(struct RaSha2Ctx *ctx);
void RaSha256Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);
void RaSha256Finish(struct RaSha2Ctx *ctx, /*out*/uint8_t data[32]);
void RaSha256(const uint8_t *data, int len, /*out*/uint8_t output[32]);

void RaSha512Init(struct RaSha2Ctx *ctx);
void RaSha512Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);
void RaSha512Finish(struct RaSha2Ctx *ctx, /*out*/uint8_t data[64]);
void RaSha512(const uint8_t *data, int len, /*out*/uint8_t output[64]);

#ifdef __cplusplus
}
#endif


#endif
