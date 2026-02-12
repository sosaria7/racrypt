/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef RACRYPT_TEST_VECTOR_H
#define RACRYPT_TEST_VECTOR_H

#include <stdint.h>

// Magic and version
#define TVEC_MAGIC 0x43455654  // "TVEC"
#define TVEC_VERSION 1

// Algorithm IDs
#define TVEC_ALG_AES    0
#define TVEC_ALG_ARIA   1
#define TVEC_ALG_SEED   2
#define TVEC_ALG_DES    3
#define TVEC_ALG_3DES   4
#define TVEC_ALG_BLOWFISH 5

// Mode IDs
#define TVEC_MODE_ECB   0
#define TVEC_MODE_CBC   1
#define TVEC_MODE_CFB   2
#define TVEC_MODE_OFB   3
#define TVEC_MODE_CTR   4
#define TVEC_MODE_GCM   5

// Maximum lengths
#define TVEC_MAX_KEY_LEN 32
#define TVEC_MAX_IV_LEN 16
#define TVEC_MAX_DATA_LEN 1024
#define TVEC_MAX_AAD_LEN 256
#define TVEC_MAX_TAG_LEN 16

// File header (12 bytes)
typedef struct {
	uint32_t magic;      // "TVEC" (0x43455654)
	uint32_t version;    // Format version
	uint32_t count;      // Number of test vectors
} TvecHeader;

// Entry header (16 bytes)
typedef struct {
	uint8_t algorithm;        // Algorithm ID
	uint8_t mode;             // Mode ID
	uint8_t key_len;          // Key length
	uint8_t iv_len;           // IV length
	uint16_t plaintext_len;   // Plaintext length
	uint16_t ciphertext_len;  // Ciphertext length
	uint16_t aad_len;         // AAD length (GCM)
	uint16_t tag_len;         // Tag length (GCM)
	uint16_t reserved1;       // Reserved for future use
	uint16_t reserved2;       // Reserved for alignment
} TvecEntryHeader;

// Test vector (in-memory representation)
typedef struct {
	uint8_t algorithm;
	uint8_t mode;
	
	uint8_t key[TVEC_MAX_KEY_LEN];
	uint8_t key_len;
	
	uint8_t iv[TVEC_MAX_IV_LEN];
	uint8_t iv_len;
	
	uint8_t plaintext[TVEC_MAX_DATA_LEN];
	uint16_t plaintext_len;
	
	uint8_t ciphertext[TVEC_MAX_DATA_LEN];
	uint16_t ciphertext_len;
	
	uint8_t aad[TVEC_MAX_AAD_LEN];
	uint16_t aad_len;
	
	uint8_t tag[TVEC_MAX_TAG_LEN];
	uint16_t tag_len;
} TestVector;

/**
 * @brief Load test vectors from binary file
 * 
 * @param filename Path to binary test vector file
 * @param vectors Output array (must be pre-allocated)
 * @param max_count Maximum number of vectors to load
 * @param count Output: actual number of vectors loaded
 * @return 0 on success, negative on error
 */
int TvecLoad(const char *filename, TestVector *vectors, int max_count, int *count);

/**
 * @brief Free resources (currently no-op, for future use)
 */
void TvecFree(TestVector *vectors, int count);

#endif // RACRYPT_TEST_VECTOR_H
