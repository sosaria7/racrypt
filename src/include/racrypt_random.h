/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_RANDOM_H__
#define __RA_RANDOM_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
* RaRandom is a pseudo random number generator based on Lehmer random number generator
*/

enum RaRandomAlgorithm {
	RA_RAND_SHA160,
	RA_RAND_SHA256,
	RA_RAND_SHA512,
	RA_RAND_MD5
};

#define RA_RAND_BUFFER_SIZE		64				// RA_DGST_LEN_SHA2_512
struct RaRandom {
	void *alg_ctx;
	enum RaRandomAlgorithm algorithm;
	int buffer_len;
	int buffer_offset;
	int count;
	uint8_t buffer[RA_RAND_BUFFER_SIZE];
};

/**
* @brief Create random context
*
* @param ctx		random context
*/
int RaRandomCreate(enum RaRandomAlgorithm algorithm, uint8_t *seed, int seed_len, struct RaRandom **ctxp);

/**
* @brief Destroy random context
*
* @param ctx		random context
*/
void RaRandomDestroy(struct RaRandom *ctx);

/**
* @brief Get random bytes
*
* @param ctx		random context
* @param len		number of bytes to get
* @param buffer		buffer to get random bytes
*/
void RaRandomBytes(struct RaRandom *ctx, int len, /*out*/uint8_t *buffer);

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
