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
* @brief Create random number generator context
*
* @param algorithm	hash algorithm to use for random generation
* @param seed		initial seed data
* @param seed_len	length of seed data
* @param ctxp		pointer for receiving random context
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaRandomCreate(enum RaRandomAlgorithm algorithm, uint8_t *seed, int seed_len, struct RaRandom **ctxp);

/**
* @brief Destroy random number generator context
*
* @param ctx		random context to destroy
*/
void RaRandomDestroy(struct RaRandom *ctx);

/**
* @brief Generate random bytes
*
* @param ctx		random number generator context
* @param len		number of bytes to generate
* @param buffer		output buffer for random bytes
*/
void RaRandomBytes(struct RaRandom *ctx, int len, /*out*/uint8_t *buffer);

/**
* @brief Generate random real number between 0 and 1
*
* @param ctx		random number generator context
* @return			random real number between 0 to 1, not including 0 and 1
*/
double RaRandom(struct RaRandom *ctx);

/**
* @brief Generate random integer number within range
*
* @param ctx		random number generator context
* @param min		minimum value (inclusive)
* @param max		maximum value (inclusive)
* @return			random integer number between min and max, including min and max
*/
uint32_t RaRandomInt(struct RaRandom *ctx, uint32_t min, uint32_t max);

#ifdef __cplusplus
}
#endif

#endif
