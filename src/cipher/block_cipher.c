/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdlib.h>
#include <string.h>

// Forward declarations for GCM helper functions
static void _GhashMultiply(uint32_t result[4], const uint32_t X[4], const uint32_t Y[4]);
static void _GhashUpdate(RaGcmState *gcm, const uint8_t block[16]);
static void _GcmIncrementCounter(uint32_t counter[4]);
static void _GcmComputeJ0FromIV(struct RaBlockCipher *ctx, const uint8_t *iv, int iv_len);


static void RaBlockCipherEncryptBlock(struct RaBlockCipher *ctx, const uint8_t *input, int input_len, uint8_t *output)
{
	uint32_t tmpInput[RA_BLOCK_LEN_MAX / 4];
	uint32_t tmpOutput[RA_BLOCK_LEN_MAX / 4];
	int i;

	// Input validation
	if (input_len <= 0 || input_len > ctx->blockSize) {
		return;
	}

	switch (ctx->opMode) {
	case RA_BLOCK_MODE_ECB: default:
		// Block mode: requires complete block
		if (input_len != ctx->blockSize) return;
		ctx->encryptBlock(ctx, input, output);
		break;
		
	case RA_BLOCK_MODE_CBC:
		// Block mode: requires complete block
		if (input_len != ctx->blockSize) return;
		memcpy(tmpInput, input, ctx->blockSize);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpInput[i] ^= ((uint32_t *)ctx->iv)[i];
		}
		ctx->encryptBlock(ctx, (uint8_t*)tmpInput, (uint8_t *)output);
		memcpy(ctx->iv, output, ctx->blockSize);
		break;
		
	case RA_BLOCK_MODE_CFB:
		// Stream mode: can handle partial blocks
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)tmpOutput);
		
		// XOR: 4-byte units for full block, byte-wise for partial
		if (input_len == ctx->blockSize) {
			for (i = 0; i < ctx->blockSize / 4; i++) {
				tmpOutput[i] ^= ((uint32_t*)input)[i];
			}
		} else {
			for (i = 0; i < input_len; i++) {
				((uint8_t*)tmpOutput)[i] ^= input[i];
			}
		}
		
		// Update IV: pad partial block with zeros
		if (input_len < ctx->blockSize) {
			uint8_t padded_iv[RA_BLOCK_LEN_MAX] = {0};
			memcpy(padded_iv, tmpOutput, input_len);
			memcpy(ctx->iv, padded_iv, ctx->blockSize);
		} else {
			memcpy(ctx->iv, tmpOutput, ctx->blockSize);
		}
		
		memcpy(output, tmpOutput, input_len);
		break;
		
	case RA_BLOCK_MODE_OFB:
		// Stream mode: IV always uses full block
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)ctx->iv);
		
		// XOR: 4-byte units for full block, byte-wise for partial
		if (input_len == ctx->blockSize) {
			memcpy(tmpOutput, input, ctx->blockSize);
			for (i = 0; i < ctx->blockSize / 4; i++) {
				tmpOutput[i] ^= ((uint32_t *)ctx->iv)[i];
			}
			memcpy(output, tmpOutput, ctx->blockSize);
		} else {
			for (i = 0; i < input_len; i++) {
				output[i] = input[i] ^ ((uint8_t *)ctx->iv)[i];
			}
		}
		break;
		
	case RA_BLOCK_MODE_CTR:
		// Generate keystream
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)tmpOutput);
		
		// XOR: 4-byte units for full block, byte-wise for partial
		if (input_len == ctx->blockSize) {
			memcpy(tmpInput, input, ctx->blockSize);
			for (i = 0; i < ctx->blockSize / 4; i++) {
				tmpOutput[i] ^= tmpInput[i];
			}
			memcpy(output, tmpOutput, ctx->blockSize);
		} else {
			for (i = 0; i < input_len; i++) {
				output[i] = input[i] ^ ((uint8_t *)tmpOutput)[i];
			}
		}
		// Stream mode: counter always increments
		for (i = ctx->blockSize - 1; i >= 0; i--) {
			if (++((uint8_t *)ctx->iv)[i] != 0) break;
		}
		break;
		
	case RA_BLOCK_MODE_GCM:
		// Stream mode: can handle partial blocks
		_GcmIncrementCounter(ctx->gcm.counter);
		
		// Generate keystream
		ctx->encryptBlock(ctx, (uint8_t *)ctx->gcm.counter, (uint8_t *)tmpOutput);
		
		// XOR: 4-byte units for full block, byte-wise for partial
		if (input_len == ctx->blockSize) {
			memcpy(tmpInput, input, ctx->blockSize);
			for (i = 0; i < ctx->blockSize / 4; i++) {
				tmpOutput[i] ^= tmpInput[i];
			}
			memcpy(output, tmpOutput, ctx->blockSize);
		} else {
			for (i = 0; i < input_len; i++) {
				output[i] = input[i] ^ ((uint8_t *)tmpOutput)[i];
			}
		}
		
		// Update GHASH: pad partial blocks with zeros
		if (input_len < ctx->blockSize) {
			uint8_t padded_block[16] = {0};
			memcpy(padded_block, output, input_len);
			_GhashUpdate(&ctx->gcm, padded_block);
		} else {
			_GhashUpdate(&ctx->gcm, output);
		}
		
		ctx->gcm.text_len += input_len * 8;
		break;
	}
}

static void RaBlockCipherDecryptBlock(struct RaBlockCipher *ctx, const uint8_t *input, int input_len, uint8_t *output)
{
	uint32_t tmpInput[RA_BLOCK_LEN_MAX / 4];
	uint32_t tmpOutput[RA_BLOCK_LEN_MAX / 4];
	int i;

	// Input validation
	if (input_len <= 0 || input_len > ctx->blockSize) {
		return;
	}

	switch (ctx->opMode) {
	case RA_BLOCK_MODE_ECB: default:
		// Block mode: requires complete block
		if (input_len != ctx->blockSize) return;
		ctx->decryptBlock(ctx, input, output);
		break;
		
	case RA_BLOCK_MODE_CBC:
		// Block mode: requires complete block
		if (input_len != ctx->blockSize) return;
		memcpy(tmpInput, input, ctx->blockSize);
		ctx->decryptBlock(ctx, input, (uint8_t *)tmpOutput);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpOutput[i] ^= ((uint32_t *)ctx->iv)[i];
		}
		memcpy(ctx->iv, tmpInput, ctx->blockSize);
		memcpy(output, tmpOutput, ctx->blockSize);
		break;
		
	case RA_BLOCK_MODE_CFB:
		// Stream mode: can handle partial blocks
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)tmpOutput);
		
		// Update IV: pad partial block with zeros
		if (input_len < ctx->blockSize) {
			uint8_t padded_iv[RA_BLOCK_LEN_MAX] = {0};
			memcpy(padded_iv, input, input_len);
			memcpy(ctx->iv, padded_iv, ctx->blockSize);
		} else {
			memcpy(ctx->iv, input, ctx->blockSize);
		}
		
		// XOR: 4-byte units for full block, byte-wise for partial
		if (input_len == ctx->blockSize) {
			for (i = 0; i < ctx->blockSize / 4; i++) {
				tmpOutput[i] ^= ((uint32_t *)ctx->iv)[i];
			}
			memcpy(output, tmpOutput, ctx->blockSize);
		} else {
			for (i = 0; i < input_len; i++) {
				output[i] = ((uint8_t *)tmpOutput)[i] ^ input[i];
			}
		}
		break;
		
	case RA_BLOCK_MODE_OFB:
		// Stream mode: IV always uses full block
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)ctx->iv);
		
		// XOR: 4-byte units for full block, byte-wise for partial
		if (input_len == ctx->blockSize) {
			memcpy(tmpOutput, input, ctx->blockSize);
			for (i = 0; i < ctx->blockSize / 4; i++) {
				tmpOutput[i] ^= ((uint32_t *)ctx->iv)[i];
			}
			memcpy(output, tmpOutput, ctx->blockSize);
		} else {
			for (i = 0; i < input_len; i++) {
				output[i] = input[i] ^ ((uint8_t *)ctx->iv)[i];
			}
		}
		break;
		
	case RA_BLOCK_MODE_CTR:
		// Generate keystream
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)tmpOutput);
		
		// XOR: 4-byte units for full block, byte-wise for partial
		if (input_len == ctx->blockSize) {
			memcpy(tmpInput, input, ctx->blockSize);
			for (i = 0; i < ctx->blockSize / 4; i++) {
				tmpOutput[i] ^= tmpInput[i];
			}
			memcpy(output, tmpOutput, ctx->blockSize);
		} else {
			for (i = 0; i < input_len; i++) {
				output[i] = input[i] ^ ((uint8_t *)tmpOutput)[i];
			}
		}

		// Stream mode: counter always increments
		for (i = ctx->blockSize - 1; i >= 0; i--) {
			if (++((uint8_t *)ctx->iv)[i] != 0) break;
		}
		break;
		
	case RA_BLOCK_MODE_GCM:
		// Stream mode: Update GHASH first (with ciphertext), then decrypt
		if (input_len < ctx->blockSize) {
			uint8_t padded_block[16] = {0};
			memcpy(padded_block, input, input_len);
			_GhashUpdate(&ctx->gcm, padded_block);
		} else {
			_GhashUpdate(&ctx->gcm, input);
		}
		ctx->gcm.text_len += input_len * 8;
		
		// Increment counter and decrypt
		_GcmIncrementCounter(ctx->gcm.counter);
		ctx->encryptBlock(ctx, (uint8_t *)ctx->gcm.counter, (uint8_t *)tmpOutput);
		
		// XOR: 4-byte units for full block, byte-wise for partial
		if (input_len == ctx->blockSize) {
			memcpy(tmpInput, input, ctx->blockSize);
			for (i = 0; i < ctx->blockSize / 4; i++) {
				tmpOutput[i] ^= tmpInput[i];
			}
			memcpy(output, tmpOutput, ctx->blockSize);
		} else {
			for (i = 0; i < input_len; i++) {
				output[i] = input[i] ^ ((uint8_t *)tmpOutput)[i];
			}
		}
		break;
	}
}

void RaBlockCipherInit(struct RaBlockCipher *ctx, blockCipherEncryptBlock encryptBlock, blockCipherEncryptBlock decryptBlock, enum RaBlockCipherMode opMode, int blockSize, uint32_t *iv, uint8_t *buffer)
{
	ctx->encryptBlock = encryptBlock;
	ctx->decryptBlock = decryptBlock;
	ctx->opMode = opMode;
	ctx->blockSize = blockSize;
	ctx->iv = iv;
	ctx->buffer = buffer;
	ctx->bufferFilled = 0;
	memset(ctx->iv, 0, ctx->blockSize);
	
	// Initialize GCM state if in GCM mode
	if (opMode == RA_BLOCK_MODE_GCM) {
		memset(&ctx->gcm, 0, sizeof(RaGcmState));
		ctx->gcm.state = 0; // GCM_STATE_INIT
	}
}

int RaBlockCipherEncrypt(struct RaBlockCipher *ctx, const uint8_t *input, int length, uint8_t *output)
{
	int len;
	int written_len = 0;

	if (length <= 0)
		return 0;

	if (ctx->bufferFilled + length < ctx->blockSize) {
		memcpy(ctx->buffer + ctx->bufferFilled, input, (size_t)length);
		ctx->bufferFilled += length;
		return 0;
	}
	if (ctx->bufferFilled > 0) {
		len = ctx->blockSize - ctx->bufferFilled;
		memcpy(ctx->buffer + ctx->bufferFilled, input, (size_t)len);
		RaBlockCipherEncryptBlock(ctx, ctx->buffer, ctx->blockSize, output);
		ctx->bufferFilled = 0;
		input += len;
		length -= len;
		output += ctx->blockSize;
		written_len += ctx->blockSize;
	}
	while (length >= ctx->blockSize) {
		RaBlockCipherEncryptBlock(ctx, input, ctx->blockSize, output);
		input += ctx->blockSize;
		length -= ctx->blockSize;
		output += ctx->blockSize;
		written_len += ctx->blockSize;
	}
	if (length > 0) {
		memcpy(ctx->buffer, input, (size_t)length);
		ctx->bufferFilled = length;
	}
	return written_len;
}

int RaBlockCipherEncryptFinal(struct RaBlockCipher *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType)
{
	int len;
	int written_len;

	if (length < 0)
		return 0;

	written_len = RaBlockCipherEncrypt(ctx, input, length, output);
	output += written_len;

	if (paddingType == RA_BLOCK_PADDING_PKCS7) {
		len = ctx->blockSize - ctx->bufferFilled;
		memset(ctx->buffer + ctx->bufferFilled, len, (size_t)len);
	}
	else if (paddingType == RA_BLOCK_PADDING_ZERO) {
		if (ctx->bufferFilled == 0)
			return written_len;
		len = ctx->blockSize - ctx->bufferFilled;
		memset(ctx->buffer + ctx->bufferFilled, 0, (size_t)len);
	}
	else {
		// no padding. discard incomplete data (except for stream modes)
		if (ctx->bufferFilled > 0) {
			// Stream modes can handle partial blocks
			if (ctx->opMode == RA_BLOCK_MODE_CFB || 
			    ctx->opMode == RA_BLOCK_MODE_OFB || 
			    ctx->opMode == RA_BLOCK_MODE_CTR || 
			    ctx->opMode == RA_BLOCK_MODE_GCM) {
				RaBlockCipherEncryptBlock(ctx, ctx->buffer, ctx->bufferFilled, output);
				written_len += ctx->bufferFilled;
			}
		}
		ctx->bufferFilled = 0;
		return written_len;
	}
	// clear buffer
	ctx->bufferFilled = 0;

	RaBlockCipherEncryptBlock(ctx, ctx->buffer, ctx->blockSize, output);
	written_len += ctx->blockSize;

	return written_len;
}

int RaBlockCipherDecrypt(struct RaBlockCipher *ctx, const uint8_t *input, int length, uint8_t *output)
{
	int len;
	int written_len = 0;

	if (length <= 0)
		return 0;

	if (ctx->bufferFilled + length < ctx->blockSize) {
		memcpy(ctx->buffer + ctx->bufferFilled, input, (size_t)length);
		ctx->bufferFilled += length;
		return 0;
	}
	if (ctx->bufferFilled > 0) {
		len = ctx->blockSize - ctx->bufferFilled;
		memcpy(ctx->buffer + ctx->bufferFilled, input, (size_t)len);
		RaBlockCipherDecryptBlock(ctx, ctx->buffer, ctx->blockSize, output);
		ctx->bufferFilled = 0;
		input += len;
		length -= len;
		output += ctx->blockSize;
		written_len += ctx->blockSize;
	}
	while (length >= ctx->blockSize) {
		RaBlockCipherDecryptBlock(ctx, input, ctx->blockSize, output);
		input += ctx->blockSize;
		length -= ctx->blockSize;
		output += ctx->blockSize;
		written_len += ctx->blockSize;
	}
	if (length > 0) {
		memcpy(ctx->buffer, input, (size_t)length);
		ctx->bufferFilled = length;
	}
	return written_len;
}

int RaBlockCipherDecryptFinal(struct RaBlockCipher *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType)
{
	int len;
	int written_len;
	int i;

	if (length < 0)
		return 0;

	written_len = RaBlockCipherDecrypt(ctx, input, length, output);
	
	// Handle remaining buffered data for stream modes
	if (ctx->bufferFilled > 0) {
		if (ctx->opMode == RA_BLOCK_MODE_CFB || 
		    ctx->opMode == RA_BLOCK_MODE_OFB || 
		    ctx->opMode == RA_BLOCK_MODE_CTR || 
		    ctx->opMode == RA_BLOCK_MODE_GCM) {
			RaBlockCipherDecryptBlock(ctx, ctx->buffer, ctx->bufferFilled, output + written_len);
			written_len += ctx->bufferFilled;
		}
	}

	// clear buffer
	ctx->bufferFilled = 0;
	if (written_len == 0)
		return 0;

	if (paddingType == RA_BLOCK_PADDING_PKCS7) {
		len = output[written_len - 1];
		if (len <= ctx->blockSize && len > 0) {
			for (i = written_len - 2; i >= written_len - len; i--) {
				if (output[i] != len) {
					// not valid pkcs7 padding data
					len = 0;
					break;
				}
			}
			written_len -= len;
		}
	}
	return written_len;
}

void RaBlockCipherSetIV(struct RaBlockCipher *ctx, const uint8_t *iv)
{
	memcpy(ctx->iv, iv, ctx->blockSize);
	ctx->bufferFilled = 0;
}

void RaBlockCipherGetIV(struct RaBlockCipher *ctx, /*out*/uint8_t *iv)
{
	memcpy(iv, ctx->iv, ctx->blockSize);
}
// ============================================================================
// GCM Mode Helper Functions
// ============================================================================

/**
 * @brief GF(2^128) multiplication for GHASH
 * 
 * Multiplies two 128-bit blocks in GF(2^128) using the reduction polynomial
 * x^128 + x^7 + x^2 + x + 1
 */
static void _GhashMultiply(uint32_t result[4], const uint32_t X[4], const uint32_t Y[4])
{
	uint8_t Z[16] = {0};
	uint8_t V[16];
	int i, j;
	
	// Copy Y to V (byte-wise for clarity)
	memcpy(V, Y, 16);
	
	// Process each bit of X (MSB first)
	for (i = 0; i < 128; i++) {
		// Check if bit i of X is set (process MSB to LSB)
		int byte_idx = i / 8;
		int bit_idx = 7 - (i % 8);
		
		if (((uint8_t*)X)[byte_idx] & (1 << bit_idx)) {
			// Z = Z XOR V
			for (j = 0; j < 16; j++) {
				Z[j] ^= V[j];
			}
		}
		
		// Check LSB of V
		int lsb = V[15] & 1;
		
		// V = V >> 1 (byte-wise right shift)
		for (j = 15; j > 0; j--) {
			V[j] = (V[j] >> 1) | (V[j-1] << 7);
		}
		V[0] >>= 1;
		
		// If LSB was 1, XOR with reduction polynomial 0xE1 << 120
		if (lsb) {
			V[0] ^= 0xE1;
		}
	}
	
	memcpy(result, Z, 16);
}

/**
 * @brief Update GHASH with a block of data
 */
static void _GhashUpdate(RaGcmState *gcm, const uint8_t block[16])
{
	int i;
	
	// ghash = ghash XOR block
	for (i = 0; i < 16; i++) {
		((uint8_t*)gcm->ghash)[i] ^= block[i];
	}
	
	// ghash = ghash * H
	uint32_t temp[4];
	_GhashMultiply(temp, gcm->ghash, gcm->H);
	memcpy(gcm->ghash, temp, 16);
}

/**
 * @brief Increment GCM counter (32-bit increment, big-endian)
 */
static void _GcmIncrementCounter(uint32_t counter[4])
{
	// Increment the rightmost 32 bits (bytes 12-15) as a big-endian integer
	uint8_t *c = (uint8_t*)counter;
	
	// Increment from right to left (big-endian)
	if (++c[15] == 0) {
		if (++c[14] == 0) {
			if (++c[13] == 0) {
				++c[12];
			}
		}
	}
}

/**
 * @brief Compute J0 from IV according to NIST SP 800-38D
 */
static void _GcmComputeJ0FromIV(struct RaBlockCipher *ctx, const uint8_t *iv, int iv_len)
{
	RaGcmState *gcm = &ctx->gcm;
	int i;
	
	if (iv_len == 12) {
		// If IV is 96 bits, J0 = IV || 0^31 || 1
		memcpy(gcm->J0, iv, 12);
		((uint8_t*)gcm->J0)[12] = 0;
		((uint8_t*)gcm->J0)[13] = 0;
		((uint8_t*)gcm->J0)[14] = 0;
		((uint8_t*)gcm->J0)[15] = 1;
	} else {
		// J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		memset(gcm->ghash, 0, 16);
		
		// Process complete blocks of IV
		int complete_blocks = iv_len / 16;
		for (i = 0; i < complete_blocks; i++) {
			_GhashUpdate(gcm, iv + i * 16);
		}
		
		// Process remaining bytes
		int remaining = iv_len % 16;
		if (remaining > 0) {
			uint8_t block[16] = {0};
			memcpy(block, iv + complete_blocks * 16, remaining);
			_GhashUpdate(gcm, block);
		}
		
		// Process length block [len(IV)]_64
		uint8_t len_block[16] = {0};
		uint64_t iv_len_bits = (uint64_t)iv_len * 8;
		// Big-endian encoding of bit length
		for (i = 0; i < 8; i++) {
			len_block[15 - i] = (iv_len_bits >> (i * 8)) & 0xFF;
		}
		_GhashUpdate(gcm, len_block);
		
		memcpy(gcm->J0, gcm->ghash, 16);
		memset(gcm->ghash, 0, 16);
	}
	
	// Initialize counter to J0
	memcpy(gcm->counter, gcm->J0, 16);
}

// ============================================================================
// GCM Mode Public API
// ============================================================================

int RaBlockCipherGcmSetIV(struct RaBlockCipher *ctx, const uint8_t *iv, int iv_len)
{
	RaGcmState *gcm;
	uint8_t zero_block[16] = {0};
	
	if (ctx == NULL || iv == NULL || iv_len <= 0) {
		return RA_ERR_INVALID_PARAM;
	}
	
	if (ctx->opMode != RA_BLOCK_MODE_GCM) {
		return RA_ERR_INVALID_PARAM;
	}
	
	if (ctx->blockSize != 16) {
		// GCM only supports 128-bit block ciphers
		return RA_ERR_INVALID_PARAM;
	}
	
	gcm = &ctx->gcm;
	
	// Compute H = E(K, 0^128)
	ctx->encryptBlock(ctx, zero_block, (uint8_t*)gcm->H);
	
	// Compute J0 from IV
	_GcmComputeJ0FromIV(ctx, iv, iv_len);
	
	// Reset lengths and state
	gcm->aad_len = 0;
	gcm->text_len = 0;
	gcm->state = 1; // GCM_STATE_AAD
	
	return RA_ERR_SUCCESS;
}

int RaBlockCipherGcmSetAAD(struct RaBlockCipher *ctx, const uint8_t *aad, int aad_len)
{
	RaGcmState *gcm;
	int i;
	
	if (ctx == NULL || (aad == NULL && aad_len > 0)) {
		return RA_ERR_INVALID_PARAM;
	}
	
	if (ctx->opMode != RA_BLOCK_MODE_GCM) {
		return RA_ERR_INVALID_PARAM;
	}
	
	gcm = &ctx->gcm;
	
	if (gcm->state != 1) { // Must be in GCM_STATE_AAD
		return RA_ERR_INVALID_STATE;
	}
	
	if (aad_len == 0) {
		gcm->state = 2; // GCM_STATE_TEXT
		return RA_ERR_SUCCESS;
	}
	
	// Process complete blocks
	int complete_blocks = aad_len / 16;
	for (i = 0; i < complete_blocks; i++) {
		_GhashUpdate(gcm, aad + i * 16);
	}
	
	// Process remaining bytes
	int remaining = aad_len % 16;
	if (remaining > 0) {
		uint8_t block[16] = {0};
		memcpy(block, aad + complete_blocks * 16, remaining);
		_GhashUpdate(gcm, block);
	}
	
	gcm->aad_len = (uint64_t)aad_len * 8;
	gcm->state = 2; // GCM_STATE_TEXT
	
	return RA_ERR_SUCCESS;
}

int RaBlockCipherGcmGetTag(struct RaBlockCipher *ctx, uint8_t tag[16])
{
	RaGcmState *gcm;
	uint8_t len_block[16];
	uint8_t S[16];
	int i;
	
	if (ctx == NULL || tag == NULL) {
		return RA_ERR_INVALID_PARAM;
	}
	
	if (ctx->opMode != RA_BLOCK_MODE_GCM) {
		return RA_ERR_INVALID_PARAM;
	}
	
	gcm = &ctx->gcm;
	
	if (gcm->state < 2) { // Must have processed text
		return RA_ERR_INVALID_STATE;
	}
	
	// Finalize if not already done
	if (gcm->state == 2) {
		// Process length block: [len(A)]_64 || [len(C)]_64
		memset(len_block, 0, 16);
		
		// AAD length (big-endian)
		for (i = 0; i < 8; i++) {
			len_block[7 - i] = (gcm->aad_len >> (i * 8)) & 0xFF;
		}
		
		// Text length (big-endian)
		for (i = 0; i < 8; i++) {
			len_block[15 - i] = (gcm->text_len >> (i * 8)) & 0xFF;
		}
		
		_GhashUpdate(gcm, len_block);
		
		// Compute tag: S = GHASH XOR E(K, J0)
		ctx->encryptBlock(ctx, (uint8_t*)gcm->J0, S);
		for (i = 0; i < 16; i++) {
			gcm->tag[i] = ((uint8_t*)gcm->ghash)[i] ^ S[i];
		}
		
		gcm->state = 3; // GCM_STATE_FINAL
	}
	
	memcpy(tag, gcm->tag, 16);
	
	return RA_ERR_SUCCESS;
}

int RaBlockCipherGcmVerifyTag(struct RaBlockCipher *ctx, const uint8_t tag[16])
{
	uint8_t computed_tag[16];
	int result;
	int i;
	
	if (ctx == NULL || tag == NULL) {
		return RA_ERR_INVALID_PARAM;
	}
	
	result = RaBlockCipherGcmGetTag(ctx, computed_tag);
	if (result != RA_ERR_SUCCESS) {
		return result;
	}
	
	// Constant-time comparison to prevent timing attacks
	uint8_t diff = 0;
	for (i = 0; i < 16; i++) {
		diff |= computed_tag[i] ^ tag[i];
	}
	
	// Clear computed tag
	memset(computed_tag, 0, 16);
	
	if (diff != 0) {
		return RA_ERR_VERIFY_FAILED;
	}
	
	return RA_ERR_SUCCESS;
}
