/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_BN_H__
#define __RA_BN_H__

#include "racrypt_com.h"
#include "racrypt_random.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BN_WORD_BYTE
#if __WORDSIZE == 64 || defined(_WIN64)
#define BN_WORD_BYTE	8
#else
#define BN_WORD_BYTE	4
#endif
#endif

#if BN_WORD_BYTE == 8
	typedef int64_t		bn_int_t;
	typedef uint64_t	bn_uint_t;
#else
	typedef int32_t		bn_int_t;
	typedef uint32_t	bn_uint_t;
#endif
	typedef struct {
		uint64_t	low;
		uint64_t	high;
	} bn_uint128_t;

// max_bit_len = 32 * BN_WORD_LEN
#define BN_WORD_LEN		100
#define BN_WORD_BIT		(BN_WORD_BYTE*8)				// 32 or 64
#define BN_ISZERO(bn)	((bn)->length == 1 && (bn)->data[0] == 0)
#define BN_ISONE(bn)	((bn)->length == 1 && (bn)->sign == 0 && (bn)->data[0] == 1)
#define BN_ISTWO(bn)	((bn)->length == 1 && (bn)->sign == 0 && (bn)->data[0] == 2)
#define BN_ISEVEN(bn)	(((bn)->data[0] & 1) == 0)
#define BN_ISNEG(bn)	((bn)->sign)
#define BN_SAFEFREE(bn)	{if(bn != NULL){ BnFree(bn); bn = NULL; }}

struct RaBigNumber
{
	int length;
	int max_length;
	int sign;		// 0 : positive, 1 : negative
	bn_uint_t* data;
};

/**
* @brief Create new big number with specified word length
*
* @param length		maximum word length for the big number
* @return			pointer to new big number, or NULL on failure
*/
struct RaBigNumber* BnNewW(int length);

/**
* @brief Create new big number with specified bit length
*
* @param bit		maximum bit length for the big number
* @return			pointer to new big number, or NULL on failure
*/
struct RaBigNumber* BnNew(int bit);

/**
* @brief Create a copy of existing big number
*
* @param bn			big number to clone
* @return			pointer to cloned big number, or NULL on failure
*/
struct RaBigNumber* BnClone(struct RaBigNumber* bn);

/**
* @brief Free big number memory
*
* @param bn			big number to free
*/
void BnFree(struct RaBigNumber* bn);

/**
* @brief Clear and free big number memory
*
* @param bn			big number to clear and free
*/
void BnClearFree(struct RaBigNumber* bn);

void BnSetInt(struct RaBigNumber* bn, bn_int_t value);
void BnSetInt32( struct RaBigNumber* bn, int32_t value );
void BnSetInt64(struct RaBigNumber* bn, int64_t value);
void BnSetUInt(struct RaBigNumber* bn, bn_uint_t value);
void BnSetUInt32( struct RaBigNumber* bn, uint32_t value );
void BnSetUInt64(struct RaBigNumber* bn, uint64_t value);
int BnSet(struct RaBigNumber* bn, struct RaBigNumber* bn2);
int BnSetByteArray(struct RaBigNumber* bn, const uint8_t* data, int len);
int BnSetUByteArray(struct RaBigNumber* bn, const uint8_t* data, int len);

int BnCmp(struct RaBigNumber* a, struct RaBigNumber* b);
int BnCmpInt(struct RaBigNumber* a, bn_int_t val);
int BnCmpUInt(struct RaBigNumber* a, bn_uint_t val);

int BnAdd(struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int BnSub(struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int BnDouble(struct RaBigNumber* r, struct RaBigNumber* a);
int BnMul(struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int BnSqr(struct RaBigNumber* r, struct RaBigNumber* a);
int BnMod(struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int BnDiv(struct RaBigNumber* q, struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);

int BnAddInt(struct RaBigNumber* bn, bn_int_t val);
int BnAddUInt(struct RaBigNumber* bn, bn_uint_t val);
int BnSubInt(struct RaBigNumber* bn, bn_int_t val);
int BnSubUInt(struct RaBigNumber* bn, bn_uint_t val);
int BnMulInt(struct RaBigNumber* bn, bn_int_t multiplier);
int BnMulUInt(struct RaBigNumber* bn, bn_uint_t multiplier);
int BnDivInt(struct RaBigNumber* bn, bn_int_t divisor, /*out*/bn_uint_t* remainder);
int BnDivUInt(struct RaBigNumber* bn, bn_uint_t divisor, /*out*/bn_uint_t* remainder);
int BnModUInt(struct RaBigNumber* bn, bn_uint_t divisor, /*out*/bn_uint_t* remainder);
int BnShiftL(struct RaBigNumber* bn, uint32_t bit);
int BnShiftR(struct RaBigNumber* bn, uint32_t bit);

int BnGetMaxLength(struct RaBigNumber* bn);
int BnGetLength(struct RaBigNumber* bn);
int BnGenRandom(struct RaBigNumber* bn, int bit, struct RaRandom *rnd);
int BnGetRandomOdd(struct RaBigNumber* bn, int bit, struct RaRandom *rnd);
int BnGetRandomRSA(struct RaBigNumber* bn, int bit, struct RaRandom *rnd);
int BnGenRandomByteArray(uint8_t* data, int len, struct RaRandom *rnd);

int BnToByteArray(struct RaBigNumber* bn, uint8_t* buffer, int bufferlen);
int BnToFixedByteArray(struct RaBigNumber* bn, uint8_t* buffer, int bufferlen);

int _BnAddR(struct RaBigNumber* a, struct RaBigNumber* b);
int _BnSubR(struct RaBigNumber* a, struct RaBigNumber* b);

uint32_t _BnGetUInt32(struct RaBigNumber* bn);
uint64_t _BnGetUInt64(struct RaBigNumber* bn);
bn_uint_t _BnGetUInt( struct RaBigNumber* bn );
void _BnInvert(struct RaBigNumber* bn);
int _BnGetMSBPos(bn_uint_t val);
int BnGetBitLength(struct RaBigNumber* bn);

/* gcd */
int GetGCD(/*out*/struct RaBigNumber* r, struct RaBigNumber* m, struct RaBigNumber* n);
int GetGCDEx(/*out,nullable*/struct RaBigNumber* r, /*out*/struct RaBigNumber* a, /*out*/struct RaBigNumber* b, struct RaBigNumber* m, struct RaBigNumber* n, int isUnsigned);

/* Montgomery expmod */
struct RaMontCtx;
int RaMontCreate(struct RaBigNumber* N, /*out*/struct RaMontCtx** montCtx);
void RaMontDestroy(struct RaMontCtx* ctx);
int RaMontExpMod(struct RaMontCtx* ctx, /*out*/struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int RaMontNeg(struct RaMontCtx *ctx, struct RaBigNumber *r, struct RaBigNumber *a);
int RaMontAdd(struct RaMontCtx *ctx, struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b);
int RaMontSub(struct RaMontCtx *ctx, struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b);
int RaMontMul(struct RaMontCtx *ctx, struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b);
int RaMontDiv(struct RaMontCtx *ctx, struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b);
int RaMontSqr(struct RaMontCtx *ctx, struct RaBigNumber *r, struct RaBigNumber *a);
int RaMontSqrt(struct RaMontCtx *ctx, struct RaBigNumber *r, struct RaBigNumber *a);

/* prime */
int RaGenPrimeNumber(struct RaBigNumber* bn, int bit);
int RaGenPrimeNumberEx(struct RaBigNumber* bn, int bit, int(*progress)(int count, void* userData), void* userData, struct RaRandom *rnd);
int RaIsPrimeNumber(struct RaBigNumber* bn);

#ifdef __cplusplus
}
#endif

#endif
