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
	void (*fnRaSha1Process)(struct RaSha1Ctx* ctx, const uint8_t data[64]);
};

/**
* @brief Create SHA-1 digest context
*
* @param ctxp		pointer for receiving SHA-1 context
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaSha1Create(struct RaSha1Ctx **ctxp);

/**
* @brief Destroy SHA-1 digest context
*
* @param ctx		SHA-1 context to destroy
*/
void RaSha1Destroy(struct RaSha1Ctx *ctx);

/**
* @brief Cleanup SHA-1 digest context
*
* @param ctx		SHA-1 context to cleanup
*/
void RaSha1Cleanup(struct RaSha1Ctx *ctx);

/**
* @brief Initialize SHA-1 digest context
*
* @param ctx		SHA-1 context
*/
void RaSha1Init(struct RaSha1Ctx *ctx);

/**
* @brief Update SHA-1 digest with input data
*
* @param ctx		SHA-1 context
* @param data		input data
* @param len		length of input data
*/
void RaSha1Update(struct RaSha1Ctx *ctx, const uint8_t *data, int len);

/**
* @brief Finalize SHA-1 digest and produce hash output
*
* @param ctx		SHA-1 context
* @param data		output buffer for 20-byte SHA-1 hash
*/
void RaSha1Final(struct RaSha1Ctx *ctx, /*out*/uint8_t data[20]);

/**
* @brief Compute SHA-1 hash in one operation
*
* @param data		input data
* @param len		length of input data
* @param output		output buffer for 20-byte SHA-1 hash
*/
void RaSha1(const uint8_t *data, int len, /*out*/uint8_t output[20]);

struct RaSha2Ctx
{
	uint64_t totalLen_hh;
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint64_t h[8];
	uint8_t buffer[128];
	enum RaDigestAlgorithm	algorithm;
	union {
		void (*fnRaSha256Process)(struct RaSha2Ctx* ctx, const uint8_t data[64]);
		void (*fnRaSha512Process)(struct RaSha2Ctx* ctx, const uint8_t data[128]);
	} fn;
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

/**
* @brief Create SHA-2 digest context
*
* @param algorithm	SHA-2 algorithm variant (SHA-224, SHA-256, SHA-384, SHA-512, etc.)
* @param ctxp		pointer for receiving SHA-2 context
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaSha2Create(enum RaDigestAlgorithm algorithm, struct RaSha2Ctx **ctxp);

/**
* @brief Destroy SHA-2 digest context
*
* @param ctx		SHA-2 context to destroy
*/
void RaSha2Destroy(struct RaSha2Ctx *ctx);

/**
* @brief Cleanup SHA-2 digest context
*
* @param ctx		SHA-2 context to cleanup
*/
void RaSha2Cleanup(struct RaSha2Ctx *ctx);

/**
* @brief Initialize SHA-2 digest context
*
* @param ctx		SHA-2 context
* @param algorithm	SHA-2 algorithm variant
*/
void RaSha2Init(struct RaSha2Ctx *ctx, enum RaDigestAlgorithm algorithm);

/**
* @brief Update SHA-2 digest with input data
*
* @param ctx		SHA-2 context
* @param data		input data
* @param len		length of input data
*/
void RaSha2Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);

/**
* @brief Finalize SHA-2 digest and produce hash output
*
* @param ctx		SHA-2 context
* @param output		output buffer for SHA-2 hash (size depends on algorithm)
*/
void RaSha2Final(struct RaSha2Ctx *ctx, /*out*/uint8_t *output);

/**
* @brief Initialize SHA-256 digest context
*
* @param ctx		SHA-2 context
*/
void RaSha256Init(struct RaSha2Ctx *ctx);

/**
* @brief Update SHA-256 digest with input data
*
* @param ctx		SHA-2 context
* @param data		input data
* @param len		length of input data
*/
void RaSha256Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);

/**
* @brief Finalize SHA-256 digest and produce hash output
*
* @param ctx		SHA-2 context
* @param data		output buffer for 32-byte SHA-256 hash
*/
void RaSha256Final(struct RaSha2Ctx *ctx, /*out*/uint8_t data[32]);

/**
* @brief Compute SHA-256 hash in one operation
*
* @param data		input data
* @param len		length of input data
* @param output		output buffer for 32-byte SHA-256 hash
*/
void RaSha256(const uint8_t *data, int len, /*out*/uint8_t output[32]);

/**
* @brief Initialize SHA-512 digest context
*
* @param ctx		SHA-2 context
*/
void RaSha512Init(struct RaSha2Ctx *ctx);

/**
* @brief Update SHA-512 digest with input data
*
* @param ctx		SHA-2 context
* @param data		input data
* @param len		length of input data
*/
void RaSha512Update(struct RaSha2Ctx *ctx, const uint8_t *data, int len);

/**
* @brief Finalize SHA-512 digest and produce hash output
*
* @param ctx		SHA-2 context
* @param output		output buffer for 64-byte SHA-512 hash
*/
void RaSha512Final(struct RaSha2Ctx *ctx, /*out*/uint8_t output[64]);

/**
* @brief Compute SHA-512 hash in one operation
*
* @param data		input data
* @param len		length of input data
* @param output		output buffer for 64-byte SHA-512 hash
*/
void RaSha512(const uint8_t *data, int len, /*out*/uint8_t output[64]);

struct RaMd5Ctx
{
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint32_t h[4];
	uint8_t buffer[64];
};

/**
* @brief Create MD5 digest context
*
* @param ctxp		pointer for receiving MD5 context
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaMd5Create(struct RaMd5Ctx **ctxp);

/**
* @brief Destroy MD5 digest context
*
* @param ctx		MD5 context to destroy
*/
void RaMd5Destroy( struct RaMd5Ctx *ctx );

/**
* @brief Cleanup MD5 digest context
*
* @param ctx		MD5 context to cleanup
*/
void RaMd5Cleanup(struct RaMd5Ctx *ctx);

/**
* @brief Initialize MD5 digest context
*
* @param ctx		MD5 context
*/
void RaMd5Init(struct RaMd5Ctx *ctx);

/**
* @brief Update MD5 digest with input data
*
* @param ctx		MD5 context
* @param data		input data
* @param len		length of input data
*/
void RaMd5Update(struct RaMd5Ctx *ctx, const uint8_t *data, int len);

/**
* @brief Finalize MD5 digest and produce hash output
*
* @param ctx		MD5 context
* @param data		output buffer for 16-byte MD5 hash
*/
void RaMd5Final(struct RaMd5Ctx *ctx, /*out*/uint8_t data[16]);

/**
* @brief Compute MD5 hash in one operation
*
* @param data		input data
* @param len		length of input data
* @param output		output buffer for 16-byte MD5 hash
*/
void RaMd5(const uint8_t *data, int len, /*out*/uint8_t output[16]);

struct RaMd4Ctx
{
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint32_t h[4];
	uint8_t buffer[64];
};

/**
* @brief Create MD4 digest context
*
* @param ctxp		pointer for receiving MD4 context
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaMd4Create(struct RaMd4Ctx **ctxp);

/**
* @brief Destroy MD4 digest context
*
* @param ctx		MD4 context to destroy
*/
void RaMd4Destroy( struct RaMd4Ctx *ctx );

/**
* @brief Cleanup MD4 digest context
*
* @param ctx		MD4 context to cleanup
*/
void RaMd4Cleanup(struct RaMd4Ctx *ctx);

/**
* @brief Initialize MD4 digest context
*
* @param ctx		MD4 context
*/
void RaMd4Init(struct RaMd4Ctx *ctx);

/**
* @brief Update MD4 digest with input data
*
* @param ctx		MD4 context
* @param data		input data
* @param len		length of input data
*/
void RaMd4Update(struct RaMd4Ctx *ctx, const uint8_t *data, int len);

/**
* @brief Finalize MD4 digest and produce hash output
*
* @param ctx		MD4 context
* @param data		output buffer for 16-byte MD4 hash
*/
void RaMd4Final(struct RaMd4Ctx *ctx, /*out*/uint8_t data[16]);

/**
* @brief Compute MD4 hash in one operation
*
* @param data		input data
* @param len		length of input data
* @param output		output buffer for 16-byte MD4 hash
*/
void RaMd4(const uint8_t *data, int len, /*out*/uint8_t output[16]);

struct RaMd2Ctx
{
	uint32_t totalLen;
	uint8_t	state[16];
	uint8_t checksum[16];
	uint8_t buffer[16];
};

/**
* @brief Create MD2 digest context
*
* @param ctxp		pointer for receiving MD2 context
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaMd2Create(struct RaMd2Ctx **ctxp);

/**
* @brief Destroy MD2 digest context
*
* @param ctx		MD2 context to destroy
*/
void RaMd2Destroy( struct RaMd2Ctx *ctx );

/**
* @brief Cleanup MD2 digest context
*
* @param ctx		MD2 context to cleanup
*/
void RaMd2Cleanup(struct RaMd2Ctx *ctx);

/**
* @brief Initialize MD2 digest context
*
* @param ctx		MD2 context
*/
void RaMd2Init(struct RaMd2Ctx *ctx);

/**
* @brief Update MD2 digest with input data
*
* @param ctx		MD2 context
* @param data		input data
* @param len		length of input data
*/
void RaMd2Update(struct RaMd2Ctx *ctx, const uint8_t *data, int len);

/**
* @brief Finalize MD2 digest and produce hash output
*
* @param ctx		MD2 context
* @param data		output buffer for 16-byte MD2 hash
*/
void RaMd2Final(struct RaMd2Ctx *ctx, /*out*/uint8_t data[16]);

/**
* @brief Compute MD2 hash in one operation
*
* @param data		input data
* @param len		length of input data
* @param output		output buffer for 16-byte MD2 hash
*/
void RaMd2(const uint8_t *data, int len, /*out*/uint8_t output[16]);

struct RaHas160Ctx
{
	uint32_t totalLen_h;
	uint32_t totalLen_l;
	uint32_t h[5];
	uint8_t buffer[64];
};

/**
* @brief Create HAS-160 digest context
*
* @param ctxp		pointer for receiving HAS-160 context
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaHas160Create(struct RaHas160Ctx **ctxp);

/**
* @brief Destroy HAS-160 digest context
*
* @param ctx		HAS-160 context to destroy
*/
void RaHas160Destroy(struct RaHas160Ctx *ctx);

/**
* @brief Cleanup HAS-160 digest context
*
* @param ctx		HAS-160 context to cleanup
*/
void RaHas160Cleanup(struct RaHas160Ctx *ctx);

/**
* @brief Initialize HAS-160 digest context
*
* @param ctx		HAS-160 context
*/
void RaHas160Init(struct RaHas160Ctx *ctx);

/**
* @brief Update HAS-160 digest with input data
*
* @param ctx		HAS-160 context
* @param data		input data
* @param len		length of input data
*/
void RaHas160Update(struct RaHas160Ctx *ctx, const uint8_t *data, int len);

/**
* @brief Finalize HAS-160 digest and produce hash output
*
* @param ctx		HAS-160 context
* @param data		output buffer for 20-byte HAS-160 hash
*/
void RaHas160Final(struct RaHas160Ctx *ctx, /*out*/uint8_t data[20]);

/**
* @brief Compute HAS-160 hash in one operation
*
* @param data		input data
* @param len		length of input data
* @param output		output buffer for 20-byte HAS-160 hash
*/
void RaHas160(const uint8_t *data, int len, /*out*/uint8_t output[20]);

#ifdef __cplusplus
}
#endif


#endif
