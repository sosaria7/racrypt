/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_BN_H__
#define __RA_BN_H__

#include "racrypt_com.h"

#ifdef __cplusplus
extern "C" {
#endif

// max_bit_len = 32 * BN_WORD_LEN
#define BN_WORD_LEN		100
#define BN_WORD_BYTE	((int)sizeof(uint32_t))			// 4
#define BN_WORD_BIT		(BN_WORD_BYTE*8)				// 32
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
	uint32_t* data;
};

struct RaBigNumber* BnNewW(int length);
struct RaBigNumber* BnNew(int bit);
struct RaBigNumber* BnClone(struct RaBigNumber* bn);
void BnFree(struct RaBigNumber* bn);
void BnClearFree(struct RaBigNumber* bn);

void BnSetInt(struct RaBigNumber* bn, int32_t value);
void BnSetInt64(struct RaBigNumber* bn, int64_t value);
void BnSetUInt(struct RaBigNumber* bn, uint32_t value);
void BnSetUInt64(struct RaBigNumber* bn, uint64_t value);
int BnSet(struct RaBigNumber* bn, struct RaBigNumber* bn2);
int BnSetByteArray(struct RaBigNumber* bn, const uint8_t* data, int len);
int BnSetUByteArray(struct RaBigNumber* bn, const uint8_t* data, int len);

int BnCmp(struct RaBigNumber* a, struct RaBigNumber* b);
int BnCmpInt(struct RaBigNumber* a, int32_t val);
int BnCmpUInt(struct RaBigNumber* a, uint32_t val);

int BnAdd(struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int BnSub(struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int BnDouble(struct RaBigNumber* r, struct RaBigNumber* a);
int BnMul(struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int BnSqr(struct RaBigNumber* r, struct RaBigNumber* a);
int BnMod(struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);
int BnDiv(struct RaBigNumber* q, struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);

int BnAddInt(struct RaBigNumber* bn, int32_t val);
int BnAddUInt(struct RaBigNumber* bn, uint32_t val);
int BnSubInt(struct RaBigNumber* bn, int32_t val);
int BnSubUInt(struct RaBigNumber* bn, uint32_t val);
int BnMulInt(struct RaBigNumber* bn, int32_t multiplier);
int BnMulUInt(struct RaBigNumber* bn, uint32_t multiplier);
int BnDivInt(struct RaBigNumber* bn, int32_t divisor, /*out*/uint32_t* remainder);
int BnDivUInt(struct RaBigNumber* bn, uint32_t divisor, /*out*/uint32_t* remainder);
int BnModUInt(struct RaBigNumber* bn, uint32_t divisor, /*out*/uint32_t* remainder);
int BnShiftL(struct RaBigNumber* bn, uint32_t bit);
int BnShiftR(struct RaBigNumber* bn, uint32_t bit);

int BnGetMaxLength(struct RaBigNumber* bn);
int BnGetLength(struct RaBigNumber* bn);
int BnGenRandom(struct RaBigNumber* bn, int bit, uint32_t* seedp);
int BnGetRandomOdd(struct RaBigNumber* bn, int bit, uint32_t* seedp);
int BnGetRandomRSA(struct RaBigNumber* bn, int bit, uint32_t* seedp);
int BnGenRandomByteArray(uint8_t* data, int len, uint32_t* seedp);

int BnToByteArray(struct RaBigNumber* bn, uint8_t* buffer, int bufferlen);
int BnToFixedByteArray(struct RaBigNumber* bn, uint8_t* buffer, int bufferlen);

int _BnAddR(struct RaBigNumber* a, struct RaBigNumber* b);
int _BnSubR(struct RaBigNumber* a, struct RaBigNumber* b);

uint32_t _BnGetUInt32(struct RaBigNumber* bn);
uint64_t _BnGetUInt64(struct RaBigNumber* bn);
void _BnInvert(struct RaBigNumber* bn);
int _BnGetMSBPos(uint32_t val);
int BnGetBitLength(struct RaBigNumber* bn);

/* gcd */
int GetGCD(/*out*/struct RaBigNumber* r, struct RaBigNumber* m, struct RaBigNumber* n);
int GetGCDEx(/*out,nullable*/struct RaBigNumber* r, /*out*/struct RaBigNumber* a, /*out*/struct RaBigNumber* b, struct RaBigNumber* m, struct RaBigNumber* n, int isUnsigned);

/* Montgomery expmod */
struct RaMontCtx;
int RaMontCreate(struct RaBigNumber* N, /*out*/struct RaMontCtx** montCtx);
void RaMontDestroy(struct RaMontCtx* ctx);
int RaMontExpMod(struct RaMontCtx* ctx, /*out*/struct RaBigNumber* r, struct RaBigNumber* a, struct RaBigNumber* b);

/* prime */
int RaGenPrimeNumber(struct RaBigNumber* bn, int bit);
int RaGenPrimeNumberEx(struct RaBigNumber* bn, int bit, int(*progress)(int count, void* userData), void* userData, uint32_t* seedp);
int RaIsPrimeNumber(struct RaBigNumber* bn);

#ifdef __cplusplus
}
#endif

#endif