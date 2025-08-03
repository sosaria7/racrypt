/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Permutation of 0..255 constructed from the digits of pi. It gives a
"random" nonlinear byte substitution operation.
*/
static uint8_t PI_SUBST[256] = {
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

int RaMd2Create(struct RaMd2Ctx **ctxp)
{
	struct RaMd2Ctx *ctx;
	ctx = (struct RaMd2Ctx*)malloc(sizeof(struct RaMd2Ctx));
	if (ctx == NULL) {
		return RA_ERR_OUT_OF_MEMORY;
	}
	RaMd2Init(ctx);

	*ctxp = ctx;

	return RA_ERR_SUCCESS;
}

void RaMd2Destroy(struct RaMd2Ctx *ctx)
{
	if (ctx != NULL) {
		RaMd2Cleanup(ctx);
		free(ctx);
	}
}

void RaMd2Cleanup(struct RaMd2Ctx *ctx)
{
	if (ctx != NULL) {
		// Clear all sensitive data including hash state and internal buffers
		memset(ctx, 0, sizeof(struct RaMd2Ctx));
	}
}

void RaMd2Init(struct RaMd2Ctx *ctx)
{
	ctx->totalLen = 0;
	memset(ctx->state, 0, sizeof(ctx->state));
	memset(ctx->checksum, 0, sizeof(ctx->checksum));
}

static void RaMd2Process(struct RaMd2Ctx *ctx, const uint8_t data[16])
{
	uint8_t x[48];
	int i, j, t;

	/* Form encryption block from state, block, state ^ block.
	*/
	memcpy(x, ctx->state, 16);
	memcpy(x + 16, data, 16);
	for (i = 0; i < 16; i++) {
		x[i + 32] = (uint8_t)(ctx->state[i] ^ data[i]);
	}

	/* Encrypt block (18 rounds).
	*/
	t = 0;
	for (i = 0; i < 18; i++) {
		for (j = 0; j < 48; j++)
			t = x[j] ^= PI_SUBST[t];
		t = (t + i) & 0xff;
	}

	/* Save new state */
	memcpy(ctx->state, x, 16);

	/* Update checksum.
	*/
	t = ctx->checksum[15];
	for (i = 0; i < 16; i++)
		t = ctx->checksum[i] ^= PI_SUBST[data[i] ^ t];
}


void RaMd2Update(struct RaMd2Ctx *ctx, const uint8_t *data, int len)
{
	int bufferFilled;
	int bufferRemain;
	bufferFilled = ctx->totalLen & 0x0f;
	bufferRemain = 16 - bufferFilled;

	ctx->totalLen += len;

	if (bufferRemain < 16 && bufferRemain <= len) {
		memcpy(ctx->buffer + bufferFilled, data, bufferRemain);
		RaMd2Process(ctx, ctx->buffer);
		data += bufferRemain;
		len -= bufferRemain;
		bufferFilled = 0;
	}
	while (len >= 16) {
		RaMd2Process(ctx, data);
		data += 16;
		len -= 16;
	}
	if (len > 0)
		memcpy(ctx->buffer + bufferFilled, data, len);
}

void RaMd2Final(struct RaMd2Ctx *ctx, /*out*/uint8_t output[16])
{
	int bufferFilled;
	int bufferRemain;

	bufferFilled = ctx->totalLen & 0x0f;
	bufferRemain = 16 - bufferFilled;
	
	memset(ctx->buffer + bufferFilled, bufferRemain, bufferRemain);
	RaMd2Process(ctx, ctx->buffer);

	RaMd2Process(ctx, ctx->checksum);

	memcpy(output, ctx->state, 16);
}

void RaMd2(const uint8_t *data, int len, /*out*/uint8_t output[16])
{
	struct RaMd2Ctx ctx;
	RaMd2Init(&ctx);
	RaMd2Update(&ctx, data, len);
	RaMd2Final(&ctx, output);
}
