/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#pragma once
#ifndef __RA_COM_H__
#define __RA_COM_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// max_bit_len = 32 * BN_WORD_LEN
#define BN_WORD_LEN		100
#define BN_WORD_BIT		((int)sizeof(uint32_t)*8)		// 32
#define BN_ISZERO(bn)	((bn)->length == 1 && (bn)->data[0] == 0)
#define BN_ISONE(bn)	((bn)->length == 1 && (bn)->sign == 0 && (bn)->data[0] == 1)
#define BN_ISNEG(bn)	((bn)->sign)
#define BN_SAFEFREE(bn)	{if(bn != NULL){ BnFree(bn); bn = NULL; }}

#define BN_ERR_SUCCESS						(0)
#define BN_ERR_DIVIDED_BY_ZERO				(-1)
#define BN_ERR_OUT_OF_MEMORY				(-2)
#define BN_ERR_OUT_OF_BUFFER				(-3)
#define BN_ERR_NUMBER_SIZE					(-4)
#define BN_ERR_INVALID_PARAM				(-5)
#define BN_ERR_INVALID_DATA					(-6)

//struct BigNumber;
struct BigNumber
{
	int length;
	int max_length;
	int sign;		// 0 : positive, 1 : negative
	uint32_t *data;
};

struct BigNumber* BnNewW(int length);
struct BigNumber* BnNew(int bit);
struct BigNumber* BnClone(struct BigNumber *bn);
void BnFree(struct BigNumber* bn);
void BnClearFree(struct BigNumber* bn);

void BnSetInt(struct BigNumber *bn, int32_t value);
void BnSetInt64(struct BigNumber *bn, int64_t value);
void BnSetUInt(struct BigNumber *bn, uint32_t value);
void BnSetUInt64(struct BigNumber *bn, uint64_t value);
int BnSet(struct BigNumber *bn, struct BigNumber *bn2);
int BnSetByteArray(struct BigNumber *bn, const uint8_t *data, int len);
int BnSetUByteArray(struct BigNumber *bn, const uint8_t *data, int len);

int BnCmp(struct BigNumber *a, struct BigNumber *b);
int BnCmpInt(struct BigNumber *a, int32_t val);
int BnCmpUInt(struct BigNumber *a, uint32_t val);

int BnAdd(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);
int BnSub(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);
int BnDouble(struct BigNumber *r, struct BigNumber *a);
int BnMul(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);
int BnSqr(struct BigNumber *r, struct BigNumber *a);
int BnMod(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);
int BnDiv(struct BigNumber *q, struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);

int BnAddInt(struct BigNumber *bn, int32_t val);
int BnAddUInt(struct BigNumber *bn, uint32_t val);
int BnSubInt(struct BigNumber *bn, int32_t val);
int BnSubUInt(struct BigNumber *bn, uint32_t val);
int BnMulInt(struct BigNumber *bn, int32_t multiplier);
int BnMulUInt(struct BigNumber *bn, uint32_t multiplier);
int BnDivInt(struct BigNumber *bn, int32_t divisor, /*out*/uint32_t *remainder);
int BnDivUInt(struct BigNumber *bn, uint32_t divisor, /*out*/uint32_t *remainder);
int BnModUInt(struct BigNumber *bn, uint32_t divisor, /*out*/uint32_t *remainder);
int BnShiftL(struct BigNumber *bn, uint32_t bit);
int BnShiftR(struct BigNumber *bn, uint32_t bit);

int BnGetMaxLength(struct BigNumber *bn);
int BnGetLength(struct BigNumber *bn);
int BnGenRandom(struct BigNumber *bn, int bit, uint32_t *seedp);
int BnGetRandomOdd(struct BigNumber *bn, int bit, uint32_t *seedp);
int BnGetRandomRSA(struct BigNumber *bn, int bit, uint32_t *seedp);

int BnToByteArray(struct BigNumber *bn, uint8_t *buffer, int bufferlen);
int BnToFixedByteArray( struct BigNumber *bn, uint8_t *buffer, int bufferlen );
void BnPrint(struct BigNumber *bn);
void BnPrintLn(struct BigNumber *bn);
void BnPrint10(struct BigNumber *bn);
void BnPrint10Ln(struct BigNumber *bn);
int BnSPrint(struct BigNumber *bn, char *buffer, int bufferlen);
int BnSPrint10(struct BigNumber *bn, char *buffer, int bufferlen);


int _BnAddR(struct BigNumber *a, struct BigNumber *b);
int _BnSubR(struct BigNumber *a, struct BigNumber *b);

uint32_t _BnGetUInt32(struct BigNumber *bn);
uint64_t _BnGetUInt64(struct BigNumber *bn);
void _BnInvert(struct BigNumber *bn);
int _BnGetMSBPos(uint32_t val);
int BnGetBitLength(struct BigNumber *bn);

/* gcd */
int GetGCD(/*out*/struct BigNumber *r, struct BigNumber *m, struct BigNumber *n);
int GetGCDEx(/*out,nullable*/struct BigNumber *r, /*out*/struct BigNumber *a, /*out*/struct BigNumber *b, struct BigNumber *m, struct BigNumber *n, int isUnsigned);

/* Montgomery expmod */
struct MontCtx;
int MontCreate(struct BigNumber *N, /*out*/struct MontCtx **montCtx);
void MontDestroy(struct MontCtx *ctx);
int MontExpMod(struct MontCtx *ctx, /*out*/struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);

/* prime */
int GenPrimeNumber(struct BigNumber *bn, int bit);
int GenPrimeNumberEx(struct BigNumber *bn, int bit, int(*progress)(int count, void* userData), void* userData, uint32_t *seedp);
int IsPrimeNumber(struct BigNumber *bn);


#ifdef __cplusplus
}
#endif

#endif
