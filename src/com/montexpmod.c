/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <stdint.h>
#include <malloc.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <racrypt.h>

struct MontCtx
{
	struct BigNumber *N;
	struct BigNumber *NB;		// N' where NN' = -1 mod B, B = 0x100000000
	struct BigNumber *BB;		// B' where BB' = 1 mod N
	struct BigNumber *tmp;
	struct BigNumber *mul;
	uint32_t n0;				// N' % R, use this instead of N' on ((T mod R) * N') mod R 
	int Rl;						// length of R in word
};

// N must be prime number
int MontCreate(struct BigNumber *N, /*out*/struct MontCtx **montCtx)
{
	int result;
	struct MontCtx *ctx = NULL;
	struct BigNumber *B = NULL;

	if (BN_ISZERO(N)) {
		assert(0);
		result = BN_ERR_DIVIDED_BY_ZERO;
		goto _EXIT;
	}
	ctx = (struct MontCtx*)malloc(sizeof(struct MontCtx));
	if (ctx == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	B = BnNewW(2);
	if (B == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	BnSetUInt64(B, UINT64_C(0x100000000));

	ctx->N = BnClone(N);
	ctx->NB = BnNewW(B->length + 1);
	ctx->BB = BnNewW(N->length + 1);
	ctx->tmp = BnNewW(N->length * 2 + 1);
	ctx->mul = BnNewW(N->length * 2);
	if (ctx->N == NULL || ctx->NB == NULL || ctx->BB == NULL ||
		ctx->tmp == NULL || ctx->mul == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	ctx->N->sign = 0;

	// RR' - NN' = 1
	result = GetGCDEx(NULL, ctx->BB, ctx->tmp, B, ctx->N, 1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	BnSub(ctx->NB, B, ctx->tmp);

	ctx->n0 = _BnGetUInt32(ctx->NB);
	ctx->Rl = N->length;

	*montCtx = ctx;
	ctx = NULL;

	result = BN_ERR_SUCCESS;

_EXIT:
	if (ctx != NULL)
		MontDestroy(ctx);
	BN_SAFEFREE(B);

	return result;
}

void MontDestroy(struct MontCtx* ctx)
{
	if (ctx != NULL) {
		BnFree(ctx->N);
		BnFree(ctx->NB);
		BnFree(ctx->BB);
		BnFree(ctx->tmp);
		BnFree(ctx->mul);
		free(ctx);
	}
}

// r = aR mod N
int MontSet(struct MontCtx *ctx, /*out*/struct BigNumber *r, struct BigNumber *a)
{
	int result;
	if (BN_ISZERO(a))
	{
		BnSetUInt(r, 0);
		return BN_ERR_SUCCESS;
	}
	if (r->max_length < ctx->N->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}
	if (ctx->tmp->max_length < a->length + ctx->Rl) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}

	memcpy(ctx->tmp->data + ctx->Rl, a->data, sizeof(uint32_t) * a->length);
	memset(ctx->tmp->data, 0, sizeof(uint32_t) * ctx->Rl);
	ctx->tmp->length = a->length + ctx->Rl;
	ctx->tmp->sign = a->sign;
	result = BnMod(r, ctx->tmp, ctx->N);

	return result;
}

// r = a(R^-1) mod N
int MontREDC(struct MontCtx *ctx, struct BigNumber *r, struct BigNumber *a)
{
	int result;
	uint32_t m;
	int i, j;

	int c;
	uint64_t val;
	uint32_t *nd;
	uint32_t *td;

	result = BnSet(ctx->tmp, a);
	if (result != BN_ERR_SUCCESS) {
		return result;
	}

	ctx->tmp->length = ctx->N->length+ctx->Rl + 1;

	if (ctx->tmp->max_length < ctx->tmp->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}
	if (ctx->tmp->length <= a->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}

	memset(ctx->tmp->data + a->length, 0, sizeof(uint32_t) * (ctx->tmp->length - a->length));

	for (i = 0; i < ctx->Rl; i++)
	{
		// T += (m*N) << (i*32)
		val = 0;
		c = 0;

		td = &ctx->tmp->data[i];
		nd = &ctx->N->data[0];

		m = (uint32_t)((*td) * ctx->n0);		// m <- T[i] * N' mod B, where B is 0x100000000
		for (j = 0; j < ctx->N->length; j++)
		{
			val = (uint64_t)(*nd) * m + (val >> 32) + c;
			*td += (uint32_t)val;
			c = ((*td) < (uint32_t)val);

			td++;
			nd++;
		}
		val >>= 32;
		if (val > 0)
		{
			val = (uint64_t)(*td) + (uint32_t)val + c;
			*td = (uint32_t)val;
			c = (int)(val >> 32);
			td++;
		}
		while (c)
		{
			*td += c;
			c = ( (*td) == 0 );
			td++;
		}
	}

	BnShiftR(ctx->tmp, ctx->Rl * BN_WORD_BIT);
	while (ctx->tmp->data[ctx->tmp->length - 1] == 0 && ctx->tmp->length > 1) {
		ctx->tmp->length--;
	}

	if (BnCmp(ctx->tmp, ctx->N) >= 0) {
		_BnSubR(ctx->tmp, ctx->N);
	}

	result = BnSet(r, ctx->tmp);
	return result;
}

int MontSqr(struct MontCtx *ctx, struct BigNumber *r, struct BigNumber *a)
{
	int result;
	result = BnSqr(ctx->mul, a);
	if (result == BN_ERR_SUCCESS)
		result = MontREDC(ctx, r, ctx->mul);

	return result;
}

int MontMul(struct MontCtx *ctx, struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	int result;
	result = BnMul(ctx->mul, a, b);
	if (result == BN_ERR_SUCCESS)
		result = MontREDC(ctx, r, ctx->mul);

	return result;
}

#define EXP_WINDOW		8		// 2^4 / 2
#define EXP_WINDOW_BIT	4		// 4bit

int MontExpMod(struct MontCtx *ctx, /*out*/struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	int result;
	struct BigNumber *val = NULL;
	int i, j;
	uint32_t mask;
	uint32_t *bd;
	uint32_t pend;

	int pendBit;
	int oddBit;

	struct BigNumber *window[EXP_WINDOW];

	memset(window, 0, sizeof(window));

	if (a->length > ctx->N->length) {
		assert(0);
		result = BN_ERR_NUMBER_SIZE;
		goto _EXIT;
	}
	val = BnNewW(ctx->N->length + 1);
	if (val == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	for (i = 0; i < EXP_WINDOW; i++) {
		window[i] = BnNewW(ctx->N->length + 1);
		if (window[i] == NULL) {
			result = BN_ERR_OUT_OF_MEMORY;
			goto _EXIT;
		}
	}

	result = MontSet(ctx, val, a);
	if (result != BN_ERR_SUCCESS) goto _EXIT;
	MontSqr(ctx, val, val);
	result = MontSet(ctx, window[0], a);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	for (i = 1; i < EXP_WINDOW; i++) {
		MontMul(ctx, window[i], window[i-1], val);		// odd
	}

	// r = Mont(1)
	BnSetUInt(val, 1);
	result = MontSet(ctx, val, val);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	bd = &b->data[b->length - 1];
	pend = 0;
	pendBit = 0;
    oddBit = 0;
	for (i = b->length - 1; i >= 0; i--) {
		mask = (uint32_t)(1U << (BN_WORD_BIT-1));
		for (j = 0; j < BN_WORD_BIT; j++) {

			if ((*bd) & mask) {
				pend |= 1;
				oddBit = 0;
			}
			if (pend) {
				pendBit++;
				oddBit++;
				if ( pendBit >= EXP_WINDOW_BIT || (mask == 1 && i == 0)) {
					oddBit--;
					pendBit -= oddBit;
					while (pendBit-- > 0) {
						MontSqr(ctx, val, val);
					}
					pend >>= oddBit + 1;
					MontMul( ctx, val, val, window[pend] );
					while (oddBit-- > 0) {
						MontSqr(ctx, val, val);
					}
					pendBit = 0;
					oddBit = 0;
					pend = 0;
				}
				pend <<= 1;
			}
			else {
				MontSqr(ctx, val, val);
			}
			mask >>= 1;
		}
		bd--;
	}

	result = MontREDC(ctx, r, val);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = BN_ERR_SUCCESS;
_EXIT:
	BN_SAFEFREE(val);
	for (i = 0; i < EXP_WINDOW; i++) {
		BN_SAFEFREE(window[i]);
	}
	return result;
}
