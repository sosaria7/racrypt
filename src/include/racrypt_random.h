/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_RANDOM_H__
#define __RA_RANDOM_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
* RaRandom is a pseudo random number generator based on Lehmer random number generator
*/

struct RaRandom {
	uint32_t seed;
	int count;
};

/**
* @brief Create random context
*
* @param ctx		random context
*/
int RaRandomCreate(struct RaRandom **ctxp);

/**
* @brief Destroy random context
*
* @param ctx		random context
*/
void RaRandomDestroy(struct RaRandom *ctx);

/**
* @brief Initialize random context
*
* @param ctx		random context
*/
void RaRandomInit(struct RaRandom *ctx);

/**
* @brief Get random real number between 0 to 1
*
* @param ctx		Random context
* @return			random real number between 0 to 1, not including 0 and 1
*/
double RaRandom(struct RaRandom *ctx);

/**
* @brief Get random integer number between min to max
*
* @param ctx		Random context
* @return			random real number between min to max, including min and max
*/
uint32_t RaRandomInt(struct RaRandom *ctx, uint32_t min, uint32_t max);

#ifdef __cplusplus
}
#endif

#endif
