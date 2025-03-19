/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdlib.h>
#include <string.h>


static void RaBlockCipherEncryptBlock(struct RaBlockCipher *ctx, const uint8_t *input, uint8_t *output)
{
	uint32_t tmpInput[RA_BLOCK_LEN_MAX / 4];
	uint32_t tmpOutput[RA_BLOCK_LEN_MAX / 4];
	int i;

	switch (ctx->opMode) {
	case RA_BLOCK_MODE_ECB: default:
		ctx->encryptBlock(ctx, input, output);
		break;
	case RA_BLOCK_MODE_CBC:
		memcpy(tmpInput, input, ctx->blockSize);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpInput[i] ^= ((uint32_t *)ctx->iv)[i];
		}
		ctx->encryptBlock(ctx, (uint8_t*)tmpInput, (uint8_t *)output);
		memcpy(ctx->iv, output, ctx->blockSize);
		break;
	case RA_BLOCK_MODE_CFB:
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)tmpOutput);
		memcpy(tmpInput, input, ctx->blockSize);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpOutput[i] ^= tmpInput[i];
		}
		memcpy(ctx->iv, tmpOutput, ctx->blockSize);
		memcpy(output, tmpOutput, ctx->blockSize);
		break;
	case RA_BLOCK_MODE_OFB:
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)ctx->iv);
		memcpy(tmpOutput, input, ctx->blockSize);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpOutput[i] ^= ((uint32_t *)ctx->iv)[i];
		}
		memcpy(output, tmpOutput, ctx->blockSize);
		break;
	case RA_BLOCK_MODE_CTR:
		// Increment the counter byte-wise
		for (i = ctx->blockSize - 1; i >= 0; i--) {
			if (++((uint8_t *)ctx->iv)[i] != 0) break;
		}
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)tmpOutput);
		memcpy(tmpInput, input, ctx->blockSize);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpOutput[i] ^= tmpInput[i];
		}
		memcpy(output, tmpOutput, ctx->blockSize);
		break;
	}
}

static void RaBlockCipherDecryptBlock(struct RaBlockCipher *ctx, const uint8_t *input, uint8_t *output)
{
	uint32_t tmpInput[RA_BLOCK_LEN_MAX / 4];
	uint32_t tmpOutput[RA_BLOCK_LEN_MAX / 4];
	int i;

	switch (ctx->opMode) {
	case RA_BLOCK_MODE_ECB: default:
		ctx->decryptBlock(ctx, input, output);
		break;
	case RA_BLOCK_MODE_CBC:
		memcpy(tmpInput, input, ctx->blockSize);
		ctx->decryptBlock(ctx, input, (uint8_t *)tmpOutput);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpOutput[i] ^= ((uint32_t *)ctx->iv)[i];
		}
		memcpy(ctx->iv, tmpInput, ctx->blockSize);
		memcpy(output, tmpOutput, ctx->blockSize);
		break;
	case RA_BLOCK_MODE_CFB:
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)tmpOutput);
		memcpy(ctx->iv, input, ctx->blockSize);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpOutput[i] ^= ((uint32_t *)ctx->iv)[i];
		}
		memcpy(output, tmpOutput, ctx->blockSize);
		break;
	case RA_BLOCK_MODE_OFB:
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)ctx->iv);
		memcpy(tmpOutput, input, ctx->blockSize);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpOutput[i] ^= ((uint32_t *)ctx->iv)[i];
		}
		memcpy(output, tmpOutput, ctx->blockSize);
		break;
	case RA_BLOCK_MODE_CTR:
		// Increment the counter byte-wise
		for (i = ctx->blockSize - 1; i >= 0; i--) {
			if (++((uint8_t *)ctx->iv)[i] != 0) break;
		}
		ctx->encryptBlock(ctx, (uint8_t *)ctx->iv, (uint8_t *)tmpOutput);
		memcpy(tmpInput, input, ctx->blockSize);
		for (i = 0; i < ctx->blockSize / 4; i++) {
			tmpOutput[i] ^= tmpInput[i];
		}
		memcpy(output, tmpOutput, ctx->blockSize);
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
		RaBlockCipherEncryptBlock(ctx, ctx->buffer, output);
		ctx->bufferFilled = 0;
		input += len;
		length -= len;
		output += ctx->blockSize;
		written_len += ctx->blockSize;
	}
	while (length >= ctx->blockSize) {
		RaBlockCipherEncryptBlock(ctx, input, output);
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
		// no padding. discard incomplete data.
		ctx->bufferFilled = 0;
		return written_len;
	}
	// clear buffer
	ctx->bufferFilled = 0;

	RaBlockCipherEncryptBlock(ctx, ctx->buffer, output);
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
		RaBlockCipherDecryptBlock(ctx, ctx->buffer, output);
		ctx->bufferFilled = 0;
		input += len;
		length -= len;
		output += ctx->blockSize;
		written_len += ctx->blockSize;
	}
	while (length >= ctx->blockSize) {
		RaBlockCipherDecryptBlock(ctx, input, output);
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

