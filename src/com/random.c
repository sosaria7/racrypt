/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#ifdef _WIN32
#		ifndef WIN32_LEAN_AND_MEAN
#			define WIN32_LEAN_AND_MEAN
#		endif
#		include <Windows.h>
#else
#	ifdef HAVE_TIMES
#		include <unistd.h>
#		include <sys/times.h>
#	endif
#endif

static uint32_t RaRandomGetRandomSeed();
static int RaRandomInit(struct RaRandom *ctx, enum RaRandomAlgorithm algorithm, uint8_t *seed, int seed_len);
static void RaRandomUpdate(struct RaRandom *ctx, uint8_t *buffer, int buffer_len);

int RaRandomCreate(enum RaRandomAlgorithm algorithm, uint8_t *seed, int seed_len, struct RaRandom **ctxp)
{
	struct RaRandom *ctx;
	int result;
	ctx = (struct RaRandom *)malloc(sizeof(struct RaRandom));
	if (ctx == NULL) {
		return RA_ERR_OUT_OF_MEMORY;
	}
	result = RaRandomInit(ctx, algorithm, seed, seed_len);
	if (result != RA_ERR_SUCCESS) {
		memset(ctx, 0, sizeof(struct RaRandom));
		free(ctx);
		return result;
	}

	*ctxp = ctx;

	return RA_ERR_SUCCESS;
}

void RaRandomDestroy(struct RaRandom *ctx)
{
	if (ctx != NULL) {
		if (ctx->alg_ctx != NULL) {
			switch (ctx->algorithm) {
			case RA_RAND_MD5:
				RaMd5Destroy((struct RaMd5Ctx *)ctx->alg_ctx);
				break;
			case RA_RAND_SHA512:
			case RA_RAND_SHA256:
				RaSha2Destroy((struct RaSha2Ctx *)ctx->alg_ctx);
				break;
			case RA_RAND_SHA160:
			default:
				RaSha1Destroy((struct RaSha1Ctx *)ctx->alg_ctx);
				break;
			}
		}
		memset(ctx, 0, sizeof(struct RaRandom));
		free(ctx);
	}
}

static int RaRandomInit(struct RaRandom *ctx, enum RaRandomAlgorithm algorithm, uint8_t *seed, int seed_len)
{
	uint8_t default_seed[4];
	uint32_t tmp_seed;
	int result;

	memset(ctx, 0, sizeof(struct RaRandom));
	ctx->algorithm = algorithm;

	if (seed == NULL) {
		tmp_seed = RaRandomGetRandomSeed();
		default_seed[0] = (uint8_t)(tmp_seed >> 24);
		default_seed[1] = (uint8_t)(tmp_seed >> 16);
		default_seed[2] = (uint8_t)(tmp_seed >> 8);
		default_seed[3] = (uint8_t)tmp_seed;
		seed = default_seed;
		seed_len = 4;
	}
	switch (ctx->algorithm) {
	case RA_RAND_MD5:
		result = RaMd5Create((struct RaMd5Ctx **)&ctx->alg_ctx);
		ctx->buffer_len = RA_DGST_LEN_MD5;
		break;
	case RA_RAND_SHA512:
		result = RaSha2Create(RA_DGST_SHA2_512, (struct RaSha2Ctx **)&ctx->alg_ctx);
		ctx->buffer_len = RA_DGST_LEN_SHA2_512;
		break;
	case RA_RAND_SHA256:
		result = RaSha2Create(RA_DGST_SHA2_256, (struct RaSha2Ctx **)&ctx->alg_ctx);
		ctx->buffer_len = RA_DGST_LEN_SHA2_256;
		break;
	case RA_RAND_SHA160:
	default:
		result = RaSha1Create((struct RaSha1Ctx **)&ctx->alg_ctx);
		ctx->buffer_len = RA_DGST_LEN_SHA1;
		break;
	}
	if (result != RA_ERR_SUCCESS) {
		ctx->buffer_len = 0;
		return result;
	}

	RaRandomUpdate(ctx, seed, seed_len);
	return RA_ERR_SUCCESS;
}

static uint32_t RaRandomGetRandomSeed()
{
	uint32_t seed;
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 28159)
	seed = GetTickCount();
#pragma warning(pop)
#else
#	ifdef HAVE_TIMES
	struct tms ts;
	seed = (uint32_t)((uint64_t)(uint32_t)times(&ts) * 1000 / sysconf(_SC_CLK_TCK));
#	else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	seed = (uint32_t)(((uint64_t)(uint32_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000));
#	endif
#endif
	return seed * 1103515245 + 12345;
}

static void RaRandomUpdate(struct RaRandom *ctx, uint8_t *buffer, int buffer_len)
{
	uint8_t count_buffer[4];
	union {
		struct RaMd5Ctx  md5_ctx;
		struct RaSha2Ctx sha2_ctx;
		struct RaSha1Ctx sha1_ctx;
	} alg_ctx;

	count_buffer[0] = (uint8_t)(ctx->count >> 24);
	count_buffer[1] = (uint8_t)(ctx->count >> 16);
	count_buffer[2] = (uint8_t)(ctx->count >> 8);
	count_buffer[3] = (uint8_t)ctx->count;

	switch (ctx->algorithm) {
	case RA_RAND_MD5:
		RaMd5Update((struct RaMd5Ctx *)ctx->alg_ctx, buffer, buffer_len);
		RaMd5Update((struct RaMd5Ctx *)ctx->alg_ctx, count_buffer, 4);
		memcpy(&alg_ctx.md5_ctx, ctx->alg_ctx, sizeof(struct RaMd5Ctx));
		RaMd5Final(&alg_ctx.md5_ctx, ctx->buffer);
		memset(&alg_ctx.md5_ctx, 0, sizeof(struct RaMd5Ctx));
		break;
	case RA_RAND_SHA512:
	case RA_RAND_SHA256:
		RaSha2Update((struct RaSha2Ctx *)ctx->alg_ctx, buffer, buffer_len);
		RaSha2Update((struct RaSha2Ctx *)ctx->alg_ctx, count_buffer, 4);
		memcpy(&alg_ctx.sha2_ctx, ctx->alg_ctx, sizeof(struct RaSha2Ctx));
		RaSha2Final(&alg_ctx.sha2_ctx, ctx->buffer);
		memset(&alg_ctx.sha2_ctx, 0, sizeof(struct RaSha2Ctx));
		break;
	case RA_RAND_SHA160:
	default:
		RaSha1Update((struct RaSha1Ctx *)ctx->alg_ctx, buffer, buffer_len);
		RaSha1Update((struct RaSha1Ctx *)ctx->alg_ctx, count_buffer, 4);
		memcpy(&alg_ctx.sha1_ctx, ctx->alg_ctx, sizeof(struct RaSha1Ctx));
		RaSha1Final(&alg_ctx.sha1_ctx, ctx->buffer);
		memset(&alg_ctx.sha1_ctx, 0, sizeof(struct RaSha1Ctx));
		break;
	}
	ctx->buffer_offset = 0;
	ctx->count++;
}

void RaRandomBytes(struct RaRandom *ctx, int len, /*out*/uint8_t *buffer)
{
	int copy_len;
	int offset = 0;
	while (len > 0) {
		if (ctx->buffer_offset >= ctx->buffer_len) {
			RaRandomUpdate(ctx, ctx->buffer, ctx->buffer_len);
		}
		copy_len = len;
		if (copy_len > ctx->buffer_len - ctx->buffer_offset) {
			copy_len = ctx->buffer_len - ctx->buffer_offset;
		}
		memcpy(buffer + offset, ctx->buffer + ctx->buffer_offset, copy_len);
		ctx->buffer_offset += copy_len;
		offset += copy_len;
		len -= copy_len;
	}
}

double RaRandom(struct RaRandom *ctx)
{
	uint32_t rnd_val;
	uint8_t rnd_buffer[4];

	do {
		RaRandomBytes(ctx, 4, rnd_buffer);
		rnd_val = (rnd_buffer[0] << 24) | (rnd_buffer[1] << 16) | (rnd_buffer[2] << 8) | rnd_buffer[3];
	} while (rnd_val == UINT32_MAX);

	return (double)rnd_val / UINT32_MAX;
}

uint32_t RaRandomInt(struct RaRandom *ctx, uint32_t min, uint32_t max)
{
	uint32_t range = max - min + 1;
	return min + (uint32_t)(range * RaRandom(ctx));
}
