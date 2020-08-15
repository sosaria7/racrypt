/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdlib.h>

int RaRc4Create(const uint8_t* key, int keyLen, struct RaRc4Ctx** ctxp)
{
	struct RaRc4Ctx *ctx;
	ctx = (struct RaRc4Ctx*)malloc(sizeof(struct RaRc4Ctx));
	if (ctx == NULL) {
		return RA_ERR_OUT_OF_MEMORY;
	}
	RaRc4Init(ctx, key, keyLen);
	
	*ctxp = ctx;

	return RA_ERR_SUCCESS;
}

void RaRc4Destroy(struct RaRc4Ctx* ctx)
{
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(struct RaRc4Ctx));
		free(ctx);
	}
}

void RaRc4Init(struct RaRc4Ctx *ctx, const uint8_t *key, int keyLen)
{
	int x;
	int y = 0;
	uint8_t tmp;
	uint8_t* S;
	uint8_t zero = 0;

	if (key == NULL || keyLen <= 0) {
		key = &zero;
		keyLen = 1;
	}

	S = ctx->S;

	for (x = 0; x < 256; x++)
		S[x] = x;

	for (x = 0; x < 256; x++) {
		y = (y + S[x] + key[x % keyLen]) % 255;

		tmp = S[x];
		S[x] = S[y];
		S[y] = tmp;
	}
	ctx->x = 0;
	ctx->y = 0;
}

static int _RaRc4(struct RaRc4Ctx* ctx, const uint8_t* input, int length, uint8_t* output)
{
	int x = 0;
	int y = 0;
	int n;
	uint8_t tmp;
	uint8_t* S;

	x = ctx->x;
	y = ctx->y;
	S = ctx->S;

	for (n = 0; n < length; n++) {
		x = (x + 1) % 256;
		y = (y + S[x]) % 256;

		tmp = S[x];
		S[x] = S[y];
		S[y] = tmp;
		
		tmp = S[(S[x] + S[y]) % 256];
		output[n] = tmp ^ input[n];
	}
	ctx->x = x;
	ctx->y = y;

	return n;
}

int RaRc4Encrypt(struct RaRc4Ctx* ctx, const uint8_t* input, int length, uint8_t* output)
{
	return _RaRc4(ctx, input, length, output);
}

int RaRc4Decrypt(struct RaRc4Ctx* ctx, const uint8_t* input, int length, uint8_t* output)
{
	return _RaRc4(ctx, input, length, output);
}
