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

#define MODULUS		2147483647
#define MULTIPLIER	48271
#define CYCLE		1021

static void RaRandomRefresh(struct RaRandom *ctx);
static uint32_t RaRandomGetRandomSeed();

int RaRandomCreate(struct RaRandom **ctxp)
{
	struct RaRandom *ctx;
	ctx = (struct RaRandom *)malloc(sizeof(struct RaRandom));
	if (ctx == NULL) {
		return RA_ERR_OUT_OF_MEMORY;
	}
	RaRandomInit(ctx);

	*ctxp = ctx;

	return RA_ERR_SUCCESS;
}

void RaRandomDestroy(struct RaRandom *ctx)
{
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(struct RaRandom));
		free(ctx);
	}
}

void RaRandomInit(struct RaRandom *ctx)
{
	ctx->count = 0;
	ctx->seed = 0;
	RaRandomRefresh(ctx);
}

static uint32_t RaRandomGetRandomSeed()
{
	uint32_t seed;
#ifdef _WIN32
	seed = GetTickCount();
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
	return seed;
}

static void RaRandomRefresh(struct RaRandom *ctx)
{
	do {
		ctx->seed ^= RaRandomGetRandomSeed();
		ctx->seed = ((ctx->seed * 1103515245) + 12345) % MODULUS;
	} while (ctx->seed == 0);
}

double RaRandom(struct RaRandom *ctx)
{
	uint32_t rndVal;
	ctx->seed = (uint32_t)((MULTIPLIER * (uint64_t)ctx->seed) % MODULUS);

	rndVal = ctx->seed;

	ctx->count++;
	if (ctx->count >= CYCLE) {
		RaRandomRefresh(ctx);
		ctx->count = 0;
	}
	return (double)rndVal / MODULUS;
}

uint32_t RaRandomInt(struct RaRandom *ctx, uint32_t min, uint32_t max)
{
	uint32_t range = max - min + 1;
	return min + (uint32_t)(range * RaRandom(ctx));
}
