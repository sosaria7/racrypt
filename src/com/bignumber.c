/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <assert.h>

static int _BnAdd(struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b);
static int _BnSub(struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b);
static int _BnCmp(struct RaBigNumber *a, struct RaBigNumber *b);
//static int _BnDoubleR(struct RaBigNumber *r);
static int _BnAddUInt(struct RaBigNumber *a, bn_uint_t val);
static int _BnSubUInt(struct RaBigNumber *a, bn_uint_t val);
static int _BnGetMSBPos32(uint32_t val);

#if BN_WORD_BYTE == 8
static int _BnGetMSBPos64(uint64_t val);
static void _BnMul128(bn_uint128_t* r, uint64_t a, uint64_t b);
static uint64_t _BnDiv128(bn_uint128_t a, uint64_t b, uint64_t* remainder);
//static void _BnAdd128(bn_uint128_t* r, bn_uint128_t a, uint64_t b);
//static void _BnSub128(bn_uint128_t* r, bn_uint128_t a, uint64_t b);
#endif

struct RaBigNumber * BnNewW(int length)
{
	struct RaBigNumber * bn;
	if (length <= 0)
		length = BN_WORD_LEN;		// default length
	else if (length < 2)
		length = 2;					// minimum length is 2 (64bit or 128bit)
	bn = (struct RaBigNumber *)malloc(sizeof(struct RaBigNumber) + sizeof(bn_uint_t) * length);
	if (bn == NULL)
		return NULL;
	bn->data = (bn_uint_t*)(bn + 1);
	bn->data[0] = 0;
	bn->length = 1;
	bn->sign = 0;
	bn->max_length = length;
	return bn;
}

struct RaBigNumber * BnNew(int bit)
{
	int word;
	word = (bit + BN_WORD_BIT - 1) / BN_WORD_BIT;
	return BnNewW(word);
}

struct RaBigNumber * BnClone(struct RaBigNumber *bn)
{
	struct RaBigNumber *new_bn;

	new_bn = BnNewW(bn->max_length);
	if (new_bn != NULL)
		BnSet(new_bn, bn);
	return new_bn;
}

void BnFree(struct RaBigNumber * bn)
{
	free(bn);
}

void BnClearFree(struct RaBigNumber* bn)
{
	memset(bn, 0, sizeof(struct RaBigNumber) + sizeof(bn_uint_t) * bn->max_length);
	free(bn);
}

void BnSetInt(struct RaBigNumber *bn, bn_int_t value)
{
	if (value < 0) {
		bn->sign = 1;
		value = -value;
	}
	else {
		bn->sign = 0;
	}
	bn->data[0] = (bn_uint_t)value;
	bn->length = 1;
}

void BnSetInt32(struct RaBigNumber *bn, int32_t value)
{
	if (value < 0) {
		bn->sign = 1;
		value = -value;
	}
	else {
		bn->sign = 0;
	}
	bn->data[0] = (uint32_t)value;
	bn->length = 1;
}

void BnSetInt64(struct RaBigNumber *bn, int64_t value)
{
	if (value < 0) {
		bn->sign = 1;
		value = -value;
	}
	else {
		bn->sign = 0;
	}
#if BN_WORD_BYTE == 8
	bn->data[0] = (uint64_t)value;
	bn->length = 1;
#else
	bn->data[0] = (uint32_t)value;
	bn->data[1] = (uint32_t)(value >> 32);
	bn->length = 1 + (bn->data[1] != 0);
#endif
}

void BnSetUInt(struct RaBigNumber *bn, bn_uint_t value)
{
	bn->data[0] = value;
	bn->length = 1;
	bn->sign = 0;
}

void BnSetUInt32(struct RaBigNumber *bn, uint32_t value)
{
	bn->data[0] = value;
	bn->length = 1;
	bn->sign = 0;
}

void BnSetUInt64(struct RaBigNumber *bn, uint64_t value)
{
#if BN_WORD_BYTE == 8
	bn->data[0] = value;
	bn->length = 1;
#else
	bn->data[0] = (uint32_t)value;
	bn->data[1] = (uint32_t)(value >> 32);
	bn->length = 1 + (bn->data[1] != 0);
#endif
	bn->sign = 0;
}

int BnSet(struct RaBigNumber *bn, struct RaBigNumber *bn2)
{
	if (bn->max_length < bn2->length) {
		return RA_ERR_NUMBER_SIZE;
	}
	memcpy(bn->data, bn2->data, sizeof(bn_uint_t) * bn2->length);
	bn->length = bn2->length;
	bn->sign = bn2->sign;
	return RA_ERR_SUCCESS;
}

static int _BnSetByteArray(struct RaBigNumber *bn, const uint8_t *data, int len, int isSigned)
{
	int word;
	int byte;
	const uint8_t *d;
	bn_uint_t *bd;
	const uint8_t *end;

	if (len <= 0) {
		return RA_ERR_INVALID_PARAM;
	}

	d = &data[0];
	end = &data[len];

	if (isSigned) {
		bn->sign = d[0] >> 7;
		if ( d[0] == 0x00 || d[0] == 0xff ) {
			while (len > 1 && (d[0] == data[0])) {
				d++;
				len--;
			}
		}
	}
	else {
		bn->sign = 0;
		while ( len > 1 && d[0] == 0x00 ) {
			d++;
			len--;
		}
	}

	word = (len + sizeof(bn_uint_t) - 1) / sizeof(bn_uint_t);
	byte = (len + sizeof(bn_uint_t) - 1) % sizeof(bn_uint_t);		// byte of highst word
	if (bn->max_length < word) {
		return RA_ERR_NUMBER_SIZE;
	}

	bn->length = word;

	bd = &bn->data[word-1];

	*bd = 0;
	if (bn->sign)
		*bd = ~*bd;

	switch (byte) {
#if BN_WORD_BYTE == 8
	case 7:
		*bd = (*bd << 8) | *d++;
	case 6:
		*bd = (*bd << 8) | *d++;
	case 5:
		*bd = (*bd << 8) | *d++;
	case 4:
		*bd = (*bd << 8) | *d++;
#endif
	case 3:
		*bd = (*bd << 8) | *d++;
	case 2:
		*bd = (*bd << 8) | *d++;
	case 1:
		*bd = (*bd << 8) | *d++;
	case 0:
		*bd = (*bd << 8) | *d++;
	default:
		break;
	}
	if (bn->sign)
		*bd = ~*bd;

	bd--;

	while(d < end) {
		*bd = (uint32_t)((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]);
#if BN_WORD_BYTE == 8
		* bd <<= 32;
		*bd |= (uint32_t)((d[4] << 24) | (d[5] << 16) | (d[6] << 8) | d[7]);
#endif
		if (bn->sign)
			*bd = ~*bd;
		bd--;
		d += BN_WORD_BYTE;
	}
	while( bn->length > 1 && bn->data[bn->length-1] == 0 ) {
		bn->length--;
	}
	if (bn->sign)
		BnSubInt(bn, 1);

	return RA_ERR_SUCCESS;
}

int BnSetByteArray(struct RaBigNumber *bn, const uint8_t *data, int len)
{
	return _BnSetByteArray(bn, data, len, 1);
}

int BnSetUByteArray(struct RaBigNumber *bn, const uint8_t *data, int len)
{
	return _BnSetByteArray(bn, data, len, 0);
}

// a < b : -1, a > b : 1, a = b : 0
int BnCmp(struct RaBigNumber *a, struct RaBigNumber *b)
{
	if (a->sign == 0) {
		if (b->sign == 0)
			return _BnCmp(a, b);
		else
			return 1;
	}
	else {
		if (b->sign == 0)
			return -1;
		else
			return -_BnCmp(a, b);
	}
}

int BnCmpInt(struct RaBigNumber *a, bn_int_t val)
{
	if (a->sign == 0) {
		if (a->length > 1 || val < 0)
			return 1;
		if (a->data[0] > (bn_uint_t)val)
			return 1;
		else if (a->data[0] < (bn_uint_t)val)
			return -1;
		return 0;
	}
	else {
		if (a->length > 1 || val > 0)
			return -1;
		val = -val;
		if (a->data[0] > (bn_uint_t)val)
			return -1;
		else if (a->data[0] < (bn_uint_t)val)
			return 1;
		return 0;
	}
}

int BnCmpUInt(struct RaBigNumber *a, bn_uint_t val)
{
	if (a->sign == 0) {
		if (a->length > 1)
			return 1;
		if (a->data[0] > val)
			return 1;
		else if (a->data[0] < val)
			return -1;
		return 0;
	}
	else {
		if (a->data[0] == 0)
			return 0;
		return -1;
	}
}

int BnAdd(struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b)
{
	int ret;
	if (a->sign ^ b->sign) {
		if (_BnCmp(a, b) > 0) {
			ret = _BnSub(r, a, b);
			r->sign = a->sign;
		}
		else {
			ret = _BnSub(r, b, a);
			r->sign = b->sign;
		}
	}
	else {
		ret = _BnAdd(r, a, b);
		r->sign = a->sign;
	}
	return ret;
}

// r = a - b
int BnSub(struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b)
{
	int ret;
	if (a->sign ^ b->sign) {
		ret = _BnAdd(r, a, b);
		r->sign = a->sign;
	}
	else {
		if (_BnCmp(a, b) > 0) {
			ret = _BnSub(r, a, b);
			r->sign = a->sign;
		}
		else {
			ret = _BnSub(r, b, a);
			r->sign = !a->sign;
		}
	}
	return ret;
}


int BnDouble(struct RaBigNumber *r, struct RaBigNumber *a)
{
	int i;
	int c;
	bn_uint_t *rd;
	bn_uint_t *ad;

	if (r->max_length < a->length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}

	c = 0;
	rd = &r->data[0];
	ad = &a->data[0];
	r->length = a->length;
	for (i = 0; i < a->length; i++) {
		*rd = ((*ad) << 1) + c;
		c = (int)(((*ad) >> (BN_WORD_BIT - 1)) & 1);
		ad++;
		rd++;
	}
	if (c) {
		if (r->max_length <= r->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}

		*rd = 1;
		r->length++;
	}
	r->sign = a->sign;
	return RA_ERR_SUCCESS;
}

int BnMul(struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b)
{
	int c;
	int i, j;
	int length;
	bn_uint_t *ad;
	bn_uint_t *bd;
	bn_uint_t *rd;

	if (BN_ISZERO(a) || BN_ISZERO(b)) {
		BnSetUInt(r, 0);
		return RA_ERR_SUCCESS;
	}
	
	length = (BnGetBitLength(a) + BnGetBitLength(b) + BN_WORD_BIT - 1) / BN_WORD_BIT;
	if (r->max_length < length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}

	memset(r->data, 0, sizeof(bn_uint_t) * length);

	rd = r->data;
	for (i = 0; i < b->length; i++) {
#if BN_WORD_BYTE == 8
		bn_uint128_t val;
		uint64_t cw;
		val.high = 0;
		val.low = 0;
		c = 0;

		ad = &a->data[0];
		bd = &b->data[i];
		rd = &r->data[i];

		for (j = 0; j < a->length; j++) {
			cw = val.high;
			_BnMul128(&val, *ad, *bd);
			val.low += cw;
			if (val.low < cw)
				val.high++;
			if (c != 0) {
				val.low++;
				if (val.low == 0)
					val.high++;
			}
			*rd += val.low;
			c = ((*rd) < val.low);
			rd++;
			ad++;
		}
		if (val.high > 0) {
			val.low = val.high;
			val.high = 0;
			if (c != 0) {
				val.low++;
				if (val.low == 0)
					val.high++;
			}
			*rd += val.low;
			c = ((*rd) < val.low) | (int)val.high;
			rd++;
		}
#else
		uint64_t val;
		val = 0;
		c = 0;

		ad = &a->data[0];
		bd = &b->data[i];
		rd = &r->data[i];

		for (j = 0; j < a->length; j++) {
			val = (uint64_t)(*ad) * (*bd) + (val >> 32) + c;
			*rd += (uint32_t)val;
			c = ((*rd) < (uint32_t)val);
			rd++;
			ad++;
		}
		val >>= 32;
		if (val > 0) {
			val = (uint64_t)(*rd) + val + c;
			*rd = (uint32_t)val;
			c = (int)(val >> 32);
			rd++;
		}
#endif
		while (c) {
			*rd += c;
			c = ((*rd) == 0);
			rd++;
		}
	}

	r->length = (int)(intptr_t)(rd - r->data);;
	r->sign = a->sign ^ b->sign;
	return RA_ERR_SUCCESS;
}

int BnSqr(struct RaBigNumber *r, struct RaBigNumber *a)
{
	int c;
	int i, j;
	int length;
	bn_uint_t *ad;
	bn_uint_t *bd;
	bn_uint_t *rd;

	if (BN_ISZERO(a) || BN_ISONE(a)) {
		BnSet(r, a);
		return RA_ERR_SUCCESS;
	}

	length = (BnGetBitLength(a) * 2 + BN_WORD_BIT - 1) / BN_WORD_BIT;
	if (r->max_length < length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}

	memset(r->data, 0, sizeof(bn_uint_t) * length);

	rd = r->data;
	for (i = 0; i < a->length; i++) {
#if BN_WORD_BYTE == 8
		bn_uint128_t val;
		uint64_t cw;
		val.high = 0;
		val.low = 0;
		c = 0;

		ad = &a->data[0];
		bd = &a->data[i];
		rd = &r->data[i];

		for (j = 0; j < a->length; j++) {
			cw = val.high;
			_BnMul128(&val, *ad, *bd);
			val.low += cw;
			if (val.low < cw)
				val.high++;
			if (c != 0) {
				val.low++;
				if (val.low == 0)
					val.high++;
			}
			*rd += val.low;
			c = ((*rd) < val.low);
			rd++;
			ad++;
		}
		if (val.high > 0) {
			val.low = val.high;
			val.high = 0;
			if (c != 0) {
				val.low++;
				if (val.low == 0)
					val.high++;
			}
			*rd += val.low;
			c = ((*rd) < val.low) | (int)val.high;
			rd++;
		}
#else
		uint64_t val;
		val = 0;
		c = 0;

		ad = &a->data[0];
		bd = &a->data[i];
		rd = &r->data[i];

		for (j = 0; j < a->length; j++) {
			val = (uint64_t)(*ad) * (*bd) + (val >> 32) + c;
			*rd += (uint32_t)val;
			c = ((*rd) < (uint32_t)val);
			rd++;
			ad++;
		}
		val >>= 32;
		if (val > 0) {
			val = (uint64_t)(*rd) + val + c;
			*rd = (uint32_t)val;
			c = (int)(val >> 32);
			rd++;
		}
#endif
		while (c) {
			*rd += c;
			c = ((*rd) == 0);
			rd++;
		}
	}
	r->length = (int)(intptr_t)(rd - r->data);
	r->sign = 0;

	return RA_ERR_SUCCESS;
}

// r = a % b
int BnMod(struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b)
{
	struct RaBigNumber *aa;		// a << n
	struct RaBigNumber *bb;		// b << n
	struct RaBigNumber *bq;		// b * q
	int bit;
#if BN_WORD_BYTE == 8
	bn_uint128_t ru;
#else
	uint64_t ru;
#endif
	bn_uint_t qu;
	bn_uint_t bu;
	bn_uint_t* ad;
	bn_uint_t* rd;

	if (r->max_length < b->length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}
	// divide by zero
	if (BN_ISZERO(b)) {
		assert(0);
		return RA_ERR_DIVIDED_BY_ZERO;
	}
	if (a->length < b->length) {
		BnSet(r, a);
		return RA_ERR_SUCCESS;
	}

	aa = BnNewW(a->length + 1);		// a << n
	bb = BnNewW(b->length + 1);		// b << n
	bq = BnNewW(b->length + 1);		// b * qu(32bit)

	if (aa == NULL || bb == NULL || bq == NULL) {
		BN_SAFEFREE(aa);
		BN_SAFEFREE(bb);
		BN_SAFEFREE(bq);
		return RA_ERR_OUT_OF_MEMORY;
	}

	// make (ru / bu) fit to 32bit integer (ru = highst 64bit of r, bu = highst 32bit of bb)
	// so we calculate (a<<n)/(b<<n) instead of a/b
	bit = BN_WORD_BIT - 1 - _BnGetMSBPos(b->data[b->length - 1]);
	BnSet(aa, a);
	BnSet(bb, b);
	BnShiftL(aa, (uint32_t)bit);
	BnShiftL(bb, (uint32_t)bit);

	// copy first bb->length-1 of aa->data to r
	// this reduce loop count until r gets greater than bb
	BnSetInt(r, 0);
	if (b->length > 1) {
		memcpy(r->data, aa->data + aa->length - bb->length + 1, sizeof(bn_uint_t) * ((size_t)bb->length - 1));
		r->data[bb->length] = 0;
		r->length = bb->length - 1;
	}

	bu = bb->data[bb->length - 1];		// highst word of bb
	ad = &aa->data[aa->length - bb->length];
	rd = &r->data[bb->length - 1];

#if BN_WORD_BYTE == 8
	ru.high = 0;
	ru.low = 0;

	while (ad >= aa->data) {
		BnShiftL(r, 64);
		r->data[0] = (*ad);

		// check the length
		if (r->length > b->length) {
			ru.low = *rd;
			ru.high = *(rd + 1);
		}
		else if (r->length == b->length) {
			ru.low = *rd;
			ru.high = 0;
		}
		else {
			ru.low = 0;
			ru.high = 0;
		}

		if (ru.high != 0 || ru.low >= bu) {
			qu = _BnDiv128(ru, bu, NULL);				// guess the quotient

			BnSet(bq, bb);
			BnMulUInt(bq, qu);		// bq = bb * qu
			while (_BnCmp(r, bq) < 0) {
				_BnSubR(bq, bb);
				qu--;
			}
			_BnSubR(r, bq);		// rr -= bb * qu
		}

		ad--;
	}
#else
	ru = 0;

	while (ad >= aa->data) {
		BnShiftL(r, 32);
		r->data[0] = (*ad);

		// check the length
		if (r->length > b->length)
			ru = ((uint64_t)(*(rd + 1)) << 32) | (*rd);
		else if (r->length == b->length)
			ru = *rd;
		else
			ru = 0;

		if (ru >= bu) {
			if ((ru >> 32) == bu)		// overflow
				qu = 0xFFFFFFFF;
			else
				qu = (uint32_t)(ru / bu);		// guess the quotient

			BnSet(bq, bb);
			BnMulUInt(bq, qu);		// bq = bb * qu
			while (_BnCmp(r, bq) < 0) {
				_BnSubR(bq, bb);
				qu--;
			}
			_BnSubR(r, bq);		// rr -= bb * qu
		}

		ad--;
	}
#endif

	BnShiftR(r, (uint32_t)bit);
	r->sign = a->sign;

	BnFree(aa);
	BnFree(bb);
	BnFree(bq);

	return RA_ERR_SUCCESS;
}

int BnDiv(struct RaBigNumber *q, struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b)
{
	struct RaBigNumber *rr;
	struct RaBigNumber *aa;		// a << n
	struct RaBigNumber *bb;		// b << n
	struct RaBigNumber *bq;		// b * q
	int bit;
	int length;
#if BN_WORD_BYTE == 8
	bn_uint128_t ru;
#else
	uint64_t ru;
#endif
	bn_uint_t qu;
	bn_uint_t bu;
	bn_uint_t* ad;
	bn_uint_t* qd;
	bn_uint_t* rd;

	if (r->max_length < b->length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}

	if (q->max_length <= a->length - b->length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}

	// divide by zero
	if (BN_ISZERO(b)) {
		assert(0);
		return RA_ERR_DIVIDED_BY_ZERO;
	}

	if (a->length < b->length) {
		BnSet(r, a);
		BnSetInt(q, 0);
		return RA_ERR_SUCCESS;
	}

	aa = BnNewW(a->length + 1);		// a << n
	bb = BnNewW(b->length + 1);		// b << n
	bq = BnNewW(b->length + 1);		// b * qu(32bit)
	rr = BnNewW(b->length + 1);

	if (aa == NULL || bb == NULL || bq == NULL || rr == NULL) {
		BN_SAFEFREE(aa);
		BN_SAFEFREE(bb);
		BN_SAFEFREE(bq);
		BN_SAFEFREE(rr);
		return RA_ERR_OUT_OF_MEMORY;
	}

	// make (ru / bu) fit to 32bit integer (ru = highst 64bit of r, bu = highst 32bit of bb)
	// so we calculate (a<<n)/(b<<n) instead of a/b
	bit = BN_WORD_BIT - 1 - _BnGetMSBPos(b->data[b->length - 1]);
	BnSet(aa, a);
	BnSet(bb, b);
	BnShiftL(aa, (uint32_t)bit);
	BnShiftL(bb, (uint32_t)bit);

	// copy first bb->length-1 of aa->data to rr
	// this reduce loop count until rr gets greater than bb
	BnSetInt(rr, 0);
	if(b->length > 1) {
		memcpy(rr->data, aa->data + aa->length - bb->length + 1, sizeof(bn_uint_t) * ((size_t)bb->length - 1));
		rr->data[bb->length] = 0;
		rr->length = bb->length - 1;
	}

	bu = bb->data[bb->length - 1];		// highst 32bit of bb
	qd = &q->data[aa->length - bb->length];
	ad = &aa->data[aa->length - bb->length];
	rd = &rr->data[bb->length - 1];

#if BN_WORD_BYTE == 8
	ru.high = 0;
	ru.low = 0;

	length = 0;
	while (ad >= aa->data) {
		BnShiftL(rr, 64);
		rr->data[0] = (*ad);

		if (rr->length > bb->length) {
			ru.low = *rd;
			ru.high = *(rd + 1);
		}
		else if (rr->length == bb->length) {
			ru.low = *rd;
			ru.high = 0;
		}
		else {
			ru.low = 0;
			ru.high = 0;
		}

		if (ru.high != 0 || ru.low >= bu) {
			qu = _BnDiv128(ru, bu, NULL);				// guess the quotient

			BnSet(bq, bb);
			BnMulUInt(bq, qu);		// bq = bb * qu
			while (_BnCmp(rr, bq) < 0) {
				_BnSubR(bq, bb);
				qu--;
			}
			if (qu > 0) {
				_BnSubR(rr, bq);		// rr -= bb * qu
				if (length == 0)
				{
					length = (int)(intptr_t)(qd - q->data) + 1;
				}
			}
		}
		else {
			qu = 0;
		}
		if (length > 0) {
			*qd = qu;
		}
		qd--;
		ad--;
	}
#else
	ru = 0;
	length = 0;
	while (ad >= aa->data) {
		BnShiftL(rr, 32);
		rr->data[0] = (*ad);

		if ( rr->length > bb->length )
			ru = ((uint64_t)(*(rd + 1)) << 32) | (*rd);
		else if ( rr->length == bb->length )
			ru = *rd;
		else
			ru = 0;

		if (ru >= bu) {
			if  (*(rd + 1) == bu)		// overflow
				qu = 0xFFFFFFFF;
			else
				qu = (uint32_t)(ru / bu);		// guess the quotient

			BnSet(bq, bb);
			BnMulUInt(bq, qu);		// bq = bb * qu
			while (_BnCmp(rr, bq) < 0) {
				_BnSubR(bq, bb);
				qu--;
			}
			if (qu > 0) {
				_BnSubR(rr, bq);		// rr -= bb * qu
				if (length == 0) {
					length = (int)(intptr_t)(qd - q->data) + 1;
				}
			}
		}
		else {
				qu = 0;
		}
		if (length > 0) {
			*qd = qu;
		}
		qd--;
		ad--;
	}
#endif

	q->length = length;
	if (q->length == 0) {
		q->length = 1;
		q->data[0] = 0;
	}
	q->sign = a->sign ^ b->sign;

	BnShiftR(rr, (uint32_t)bit);

	rr->sign = a->sign;
	if (q->sign && !BN_ISZERO(rr)) {
		BnSubInt(q, 1);
		BnAdd(r, rr, b);
	}
	else {
		BnSet(r, rr);
	}

	BnFree(aa);
	BnFree(bb);
	BnFree(bq);
	BnFree(rr);

	return RA_ERR_SUCCESS;
}


int BnAddInt(struct RaBigNumber *bn, bn_int_t val)
{
	int ret;
	if (val > 0) {
		if (bn->sign == 0)
			ret = _BnAddUInt(bn, (bn_uint_t)val);
		else
			ret = _BnSubUInt(bn, (bn_uint_t)val);
	}
	else {
		if (bn->sign == 0)
			ret = _BnSubUInt(bn, (bn_uint_t)-val);
		else
			ret = _BnAddUInt(bn, (bn_uint_t)-val);
	}
	return ret;
}

int BnAddUInt(struct RaBigNumber *bn, bn_uint_t val)
{
	int ret;
	if (bn->sign == 0)
		ret = _BnAddUInt(bn, val);
	else
		ret = _BnSubUInt(bn, val);
	return ret;
}

int BnSubInt(struct RaBigNumber *bn, bn_int_t val)
{
	int ret;
	if (val > 0) {
		if (bn->sign == 0)
			ret = _BnSubUInt(bn, (bn_uint_t)val);
		else
			ret = _BnAddUInt(bn, (bn_uint_t)val);
	}
	else {
		if (bn->sign == 0)
			ret = _BnAddUInt(bn, (bn_uint_t)-val);
		else
			ret = _BnSubUInt(bn, (bn_uint_t)-val);
	}
	return ret;
}

int BnSubUInt(struct RaBigNumber *bn, bn_uint_t val)
{
	int ret;
	if ( bn->sign == 0 )
		ret = _BnSubUInt( bn, val );
	else
		ret = _BnAddUInt( bn, val );
	return ret;
}

int BnMulInt(struct RaBigNumber *bn, bn_int_t multiplier)
{
#if BN_WORD_BYTE == 8
	bn_uint128_t val;
	int i;
	uint64_t cw;

	if (multiplier < 0) {
		bn->sign = -bn->sign;
		multiplier = -multiplier;
	}
	val.high = 0;
	val.low = 0;
	for (i = 0; i < bn->length; i++) {
		cw = val.high;
		_BnMul128(&val, bn->data[i], multiplier);
		val.low += cw;
		if (val.low < cw)
			val.high++;
		bn->data[i] = val.low;
	}

	if (val.high > 0) {
		if (bn->max_length <= bn->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}
		bn->data[bn->length] = val.high;
		bn->length++;
	}
#else
	uint64_t val;
	int i;

	if (multiplier < 0) {
		bn->sign = -bn->sign;
		multiplier = -multiplier;
	}
	val = 0;
	for (i = 0; i < bn->length; i++) {
		val = (uint64_t)bn->data[i] * (uint32_t)multiplier + (val >> 32);
		bn->data[i] = (uint32_t)val;
	}
	val >>= 32;
	if (val > 0) {
		if (bn->max_length <= bn->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}
		bn->data[bn->length] = (uint32_t)val;
		bn->length++;
	}
#endif
	return RA_ERR_SUCCESS;
}

int BnMulUInt(struct RaBigNumber *bn, bn_uint_t multiplier)
{
#if BN_WORD_BYTE == 8
	bn_uint128_t val;
	int i;
	uint64_t cw;

	val.high = 0;
	val.low = 0;
	for (i = 0; i < bn->length; i++) {
		cw = val.high;
		_BnMul128(&val, bn->data[i], multiplier);
		val.low += cw;
		if (val.low < cw)
			val.high++;
		bn->data[i] = val.low;
	}
	if (val.high > 0) {
		if (bn->max_length <= bn->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}
		bn->data[bn->length] = val.high;
		bn->length++;
	}
#else
	uint64_t val;
	int i;

	val = 0;
	for (i = 0; i < bn->length; i++) {
		val = (uint64_t)bn->data[i] * (uint32_t)multiplier + (val >> 32);
		bn->data[i] = (uint32_t)val;
	}
	val >>= 32;
	if (val > 0) {
		if (bn->max_length <= bn->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}
		bn->data[bn->length] = (uint32_t)val;
		bn->length++;
	}
#endif
	return RA_ERR_SUCCESS;
}

int BnDivInt(struct RaBigNumber *bn, bn_int_t divisor, /*out*/bn_uint_t *remainder)
{
#if BN_WORD_BYTE == 8
	bn_uint128_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return RA_ERR_DIVIDED_BY_ZERO;
	}
	if (divisor < 0) {
		bn->sign = -bn->sign;
		divisor = -divisor;
	}

	val.high = 0;
	val.low = 0;

	for (i = bn->length - 1; i >= 0; i--) {
		val.high = val.low;
		val.low = bn->data[i];

		if (val.high != 0 || val.low > (bn_uint_t)divisor) {
			if (length == 0)
				length = i + 1;
			bn->data[i] = _BnDiv128(val, (bn_uint_t)divisor, &val.low);
		}
		else {
			bn->data[i] = 0;
		}
	}
	if (length == 0) {
		bn->length = 1;
		bn->data[0] = 0;
	}
	else {
		bn->length = length;
	}

	if (remainder != NULL)
		*remainder = val.low;
#else
	uint64_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return RA_ERR_DIVIDED_BY_ZERO;
	}
	if (divisor < 0) {
		bn->sign = -bn->sign;
		divisor = -divisor;
	}
	val = 0;
	for (i = bn->length - 1; i >= 0; i--) {
		val = (val << 32) + bn->data[i];
		if (val > (uint32_t)divisor) {
			if (length == 0)
				length = i + 1;
			bn->data[i] = (uint32_t)(val / (uint32_t)divisor);
			val %= (uint32_t)divisor;
		}
		else {
			bn->data[i] = 0;
		}
	}
	if (length == 0) {
		bn->length = 1;
		bn->data[0] = 0;
	}
	else {
		bn->length = length;
	}

	if (remainder != NULL)
		*remainder = (uint32_t)val;
#endif
	return RA_ERR_SUCCESS;
}

int BnDivUInt(struct RaBigNumber *bn, bn_uint_t divisor, /*out*/bn_uint_t *remainder)
{
#if BN_WORD_BYTE == 8
	bn_uint128_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return RA_ERR_DIVIDED_BY_ZERO;
	}

	val.high = 0;
	val.low = 0;

	for (i = bn->length - 1; i >= 0; i--) {
		val.high = val.low;
		val.low = bn->data[i];

		if (val.high != 0 || val.low > (bn_uint_t)divisor) {
			if (length == 0)
				length = i + 1;
			bn->data[i] = _BnDiv128(val, (bn_uint_t)divisor, &val.low);
		}
		else {
			bn->data[i] = 0;
		}
	}
	if (length == 0) {
		bn->length = 1;
		bn->data[0] = 0;
	}
	else {
		bn->length = length;
	}

	if (remainder != NULL)
		*remainder = val.low;
#else
	uint64_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return RA_ERR_DIVIDED_BY_ZERO;
	}
	val = 0;
	for (i = bn->length - 1; i >= 0; i--) {
		val = (val << 32) + bn->data[i];
		if (val > (uint32_t)divisor) {
			if (length == 0)
				length = i + 1;
			bn->data[i] = (uint32_t)(val / (uint32_t)divisor);
			val %= (uint32_t)divisor;
		}
		else {
			bn->data[i] = 0;
		}
	}
	if (length == 0) {
		bn->length = 1;
		bn->data[0] = 0;
	}
	else {
		bn->length = length;
	}

	if (remainder != NULL) {
		*remainder = (uint32_t)val;
	}
#endif
	return RA_ERR_SUCCESS;
}

int BnModUInt(struct RaBigNumber *bn, bn_uint_t divisor, /*out*/bn_uint_t *remainder)
{
#if BN_WORD_BYTE == 8
	bn_uint128_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}
	val.high = 0;
	val.low = 0;
	for (i = bn->length - 1; i >= 0; i--) {
		val.high = val.low;
		val.low = bn->data[i];

		if (val.high > 0 || val.low > divisor) {
			if (length == 0)
				length = i + 1;
			_BnDiv128(val, divisor, &val.low);
		}
	}

	*remainder = val.low;
#else
	uint64_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}
	val = 0;
	for (i = bn->length - 1; i >= 0; i--) {
		val = (val << 32) + bn->data[i];
		if (val > divisor) {
			if (length == 0)
				length = i + 1;
			val %= (uint32_t)divisor;
		}
	}

	*remainder = (uint32_t)val;
#endif
	return RA_ERR_SUCCESS;
}

/////////////////////////////////////////////

int BnShiftL(struct RaBigNumber *bn, uint32_t bit)

{
	int word;
	bn_uint_t* dest;
	bn_uint_t* src;
	bn_uint_t val;
	bn_uint_t val_prev;

	if (bit == 0) {
		return RA_ERR_SUCCESS;
	}

	word = (bit + BN_WORD_BIT - 1) / BN_WORD_BIT;
	bit %= BN_WORD_BIT;

	if (bn->max_length < bn->length + word) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}

	val_prev = 0;
	dest = &bn->data[bn->length - 1 + word];
	src = &bn->data[bn->length - 1];
	if (bit > 0) {
		while (src >= bn->data) {
			val = *src;
			*dest = (val_prev << bit) | (val >> (BN_WORD_BIT - bit));
			val_prev = val;
			dest--;
			src--;
		}
		if (dest >= bn->data) {
			*dest = (val_prev << bit);
			dest--;
		}
	}
	else {
		while (src >= bn->data) {
			*dest-- = *src--;
		}
	}
	while (dest >= bn->data) {
		*dest-- = 0;
	}
	bn->length += word;
	if (bn->length > 1 && bn->data[bn->length - 1] == 0)
		bn->length--;

	return RA_ERR_SUCCESS;
}

int BnShiftR(struct RaBigNumber *bn, uint32_t bit)
{
	int word;
	bn_uint_t* dest;
	bn_uint_t* src;
	bn_uint_t* bn_end;
	bn_uint_t val;
	bn_uint_t val_prev;

	if (bit == 0) {
		return RA_ERR_SUCCESS;
	}

	word = bit / BN_WORD_BIT;
	bit %= BN_WORD_BIT;

	dest = &bn->data[0];
	src = &bn->data[word];
	bn_end = bn->data + bn->length;

	if (bit > 0) {
		val_prev = 0;
		if (src < bn_end) {
			val_prev = *src++;
		}
		while (src < bn_end) {
			val = *src;
			*dest = (val_prev >> bit) | (val << (BN_WORD_BIT - bit));
			val_prev = val;
			dest++;
			src++;
		}
		*dest++ = (val_prev >> bit);
	}
	else {
		while (src < bn_end) {
			*dest++ = *src++;
		}
	}

	bn->length = (int)(intptr_t)(dest - bn->data);
	if ( bn->length > 1 && *(--dest) == 0 )
		bn->length--;

	return RA_ERR_SUCCESS;
}

int BnGetMaxLength(struct RaBigNumber *bn)
{
	return bn->max_length;
}

int BnGetLength(struct RaBigNumber *bn)
{
	return bn->length;
}

int BnGetBitLength(struct RaBigNumber *bn)
{
	int bit;
	bit = (bn->length - 1) * BN_WORD_BIT;
	bit += _BnGetMSBPos(bn->data[bn->length - 1]) + 1;
	return bit;
}
/////////////////////////////////////////////

int BnGenRandom(struct RaBigNumber *bn, int bit, struct RaRandom *rnd)
{
	int word;

	if (bit <= 0) {
		BnSetInt(bn, 0);
		return RA_ERR_SUCCESS;
	}

	word = (bit + BN_WORD_BIT - 1) / BN_WORD_BIT;
	if (bn->max_length < word) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}

	BnGenRandomByteArray((uint8_t*)bn->data, word * BN_WORD_BYTE, rnd);

	bit %= BN_WORD_BIT;

	if (bit > 0) {
		bn->data[word - 1] &= (1 << bit) - 1;
	}
	bn->length = word;
	while (bn->length > 1 && bn->data[bn->length - 1] == 0)
		bn->length--;

	return RA_ERR_SUCCESS;
}

int BnGetRandomOdd(struct RaBigNumber *bn, int bit, struct RaRandom *rnd)
{
	int ret;

	ret = BnGenRandom(bn, bit, rnd);
	if (ret != RA_ERR_SUCCESS)
		return ret;

	bn->data[0] |= 1;
	return RA_ERR_SUCCESS;
}

int BnGetRandomRSA(struct RaBigNumber *bn, int bit, struct RaRandom *rnd)
{
	int ret;
	int word;

	ret = BnGenRandom(bn, bit, rnd);
	if (ret != RA_ERR_SUCCESS)
		return ret;

	bn->data[0] |= 1;
	word = (bit + BN_WORD_BIT - 1) / BN_WORD_BIT;
	bit = ((bit - 1) % BN_WORD_BIT);
	bn->data[word - 1] |= (bn_uint_t)1 << bit;
	bn->length = word;
	return RA_ERR_SUCCESS;
}

int BnGenRandomByteArray(uint8_t *data, int len, struct RaRandom *rnd)
{
	uint32_t random;
	int remain;
	struct RaRandom tmpRnd;

	if (rnd == NULL) {
		RaRandomInit(&tmpRnd);
		rnd = &tmpRnd;
	}

	if (len <= 0) {
		return RA_ERR_SUCCESS;
	}

	remain = (int)((uintptr_t)data % 4);

	if (len >= 4 && remain > 0) {
		random = RaRandomInt(rnd, 0, 0x00ffffff);

		switch (remain) {
		case 1:
			*data++ = (uint8_t)random;
			random >>= 8;
			len--;
		case 2:
			*data++ = (uint8_t)random;
			random >>= 8;
			len--;
		case 3:
			*data++ = (uint8_t)random;
			len--;
			break;
		}
	}

	while (len >= 4) {
		random = (RaRandomInt(rnd, 0, 0xffff) << 16) | RaRandomInt(rnd, 0, 0xffff);

		*(uint32_t*)data = random;
		data += 4;
		len -= 4;
	}

	if (len > 0) {
		random = RaRandomInt(rnd, 0, 0x00ffffff);

		switch (len) {
		case 3:
			*data++ = (uint8_t)random;
			random >>= 8;
		case 2:
			*data++ = (uint8_t)random;
			random >>= 8;
		case 1:
			*data++ = (uint8_t)random;
			break;
		}
	}

	return RA_ERR_SUCCESS;
}

/////////////////////////////////////////////
int BnToByteArray(struct RaBigNumber *bn, uint8_t *buffer, int bufferlen)
{
	int i;
	int offset;
	int bit;
	int len;
	bn_uint_t word;

	offset = 0;
	if (bn->sign && !BN_ISZERO(bn)) {
		struct RaBigNumber *neg;
		neg = BnClone(bn);
		BnAddInt(neg, 1);		// neg = ~bn + 1 = ~(bn + 1)
		word = neg->data[neg->length - 1];
		bit = _BnGetMSBPos(word);
		if ((bit % 8) == 7) {			// if most significant bit is set.
			if (buffer != NULL) {
				buffer[0] = 0xff;		// negative
			}
			offset++;
		}
		len = offset + (bit / 8 + 1) + (neg->length - 1) * BN_WORD_BYTE;
		if (buffer == NULL) {
			BnFree(neg);
			return len;
		}
		if (bufferlen < len) {
			BnFree(neg);
			return 0;
		}
		bit = (bit / 8) * 8;
		for (i = neg->length - 1; i >= 0; i--) {
			word = ~neg->data[i];
			while ( bit >= 0 ) {
				buffer[offset] = (uint8_t)(word >> bit);
				bit -= 8;
				offset++;
			}
			bit = BN_WORD_BIT - 8;
		}

		BnFree(neg);
		return offset;
	}
	else {
		word = bn->data[bn->length - 1];
		bit = _BnGetMSBPos(word);
		if ((bit % 8) == 7) {			// if most significant bit is set.
			if (buffer != NULL) {
				buffer[0] = 0x00;		// positive
			}
			offset++;
		}
		len = offset + (bit / 8 + 1) + (bn->length - 1) * BN_WORD_BYTE;
		if (buffer == NULL) {
			return len;
		}
		if (bufferlen < len) {
			return 0;
		}
		bit = (bit / 8) * 8;
		for (i = bn->length - 1; i >= 0; i--) {
			word = bn->data[i];
			while ( bit >= 0 ) {
				buffer[offset] = (uint8_t)(word >> bit);
				bit -= 8;
				offset++;
			}
			bit = BN_WORD_BIT - 8;
		}

		return offset;
	}
}

int BnToFixedByteArray( struct RaBigNumber *bn, uint8_t *buffer, int bufferlen )
{
	int i;
	int offset;
	int bit;
	int len;
	bn_uint_t word;

	// positive value only
	if ( bn->sign && !BN_ISZERO( bn ) ) {
		return 0;
	}
	word = bn->data[bn->length - 1];
	bit = _BnGetMSBPos( word );

	len = ( bit / 8 + 1 ) + ( bn->length - 1 ) * BN_WORD_BYTE;
	if ( buffer == NULL ) {
		return len;
	}
	if ( bufferlen < len ) {
		return 0;
	}
	offset = bufferlen - len;
	// fill zeros
	memset( buffer, 0, offset );

	bit = ( bit / 8 ) * 8;
	for ( i = bn->length - 1; i >= 0; i-- ) {
		word = bn->data[i];
		while ( bit >= 0 ) {
			buffer[offset] = (uint8_t)( word >> bit );
			bit -= 8;
			offset++;
		}
		bit = BN_WORD_BIT - 8;
	}

	return offset;
}

//////////////////////////////////////////////
// unsigned internal functions
static int _BnAdd(struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b)
{
	int i;
	int c;
	bn_uint_t *ad;
	bn_uint_t *bd;
	bn_uint_t *rd;
	uint64_t val;
	int al;
	int bl;

	if (r->max_length < a->length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}
	if (a->length > b->length) {
		ad = &a->data[0];
		bd = &b->data[0];
		al = a->length;
		bl = b->length;
	}
	else {
		ad = &b->data[0];
		bd = &a->data[0];
		al = b->length;
		bl = a->length;
	}

	r->length = al;
	rd = &r->data[0];
	c = 0;
	for (i = 0; i < bl; i++) {
#if BN_WORD_BYTE == 8
		val = (*ad) + (*bd);
		if (c == 0) {
			c = (val < (*ad));
		}
		else {
			val++;
			c = (val <= (*ad));
		}
		*rd = (bn_uint_t)val;
#else
		val = (uint64_t)(*ad) + (*bd) + c;
		*rd = (uint32_t)val;
		c = (int)(val >> 32);
#endif
		rd++;
		ad++;
		bd++;
	}

	// add carries
	for (; i < al && c; i++) {
		*rd = (*ad) + 1;
		c = ((*rd) == 0);
		rd++;
		ad++;
	}

	for (; i < al; i++) {
		*rd = (*ad);
		rd++;
		ad++;
	}

	if (c) {
		if (r->max_length <= r->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}

		*rd = 1;
		r->length++;
	}
	return RA_ERR_SUCCESS;
}

// r = a - b (a > b)
static int _BnSub(struct RaBigNumber *r, struct RaBigNumber *a, struct RaBigNumber *b)
{
	int i;
	int c;
	bn_uint_t *ad;
	bn_uint_t *bd;
	bn_uint_t *rd;
	uint64_t val;
	int al;
	int bl;

	ad = &a->data[0];
	bd = &b->data[0];
	al = a->length;
	bl = b->length;
	if (a->length < b->length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}
	if (r->max_length < a->length) {
		assert(0);
		return RA_ERR_NUMBER_SIZE;
	}
	r->length = al;
	rd = &r->data[0];
	c = 0;
	for (i = 0; i < bl; i++) {
#if BN_WORD_BYTE == 8
		if (c == 0) {
			c = (*ad) < (*bd);
			val = (uint64_t)(*ad) - (*bd);
		}
		else {
			c = (*ad) <= (*bd);
			val = (uint64_t)(*ad) - (*bd) - 1;
		}
		*rd = val;
#else
		val = (uint64_t)(*ad) - (*bd) + c;
		*rd = (uint32_t)val;
		c = (int)(val >> 32);
#endif
		rd++;
		ad++;
		bd++;
	}

	// sub carries
	for (; i < al && c; i++) {
		c = ((*ad) == 0);
		*rd = (*ad) - 1;
		rd++;
		ad++;
	}

	for (; i < al; i++) {
		*rd = (*ad);
		rd++;
		ad++;
	}

	while (r->length > 1 && (*(--rd)) == 0) {
		r->length--;
	}
	return RA_ERR_SUCCESS;
}

// a = a + b
int _BnAddR(struct RaBigNumber *a, struct RaBigNumber *b)
{
	int i;
	int c;
	bn_uint_t *ad;
	bn_uint_t *bd;
	uint64_t val;
	int al;
	int bl;

	ad = &a->data[0];
	bd = &b->data[0];
	al = a->length;
	bl = b->length;

	if (a->length < b->length) {
		memset(a->data + a->length, 0, sizeof(bn_uint_t) * ((size_t)b->length - a->length));
		a->length = b->length;
	}
	c = 0;
	for (i = 0; i < bl; i++) {
#if BN_WORD_BYTE == 8
		val = (*ad) + (*bd);
		if (c == 0) {
			c = (val < (*ad));
		}
		else {
			val++;
			c = (val <= (*ad));
		}
		*ad = (bn_uint_t)val;
#else
		val = (uint64_t)(*ad) + (*bd) + c;
		*ad = (uint32_t)val;
		c = (int)(val >> 32);
#endif
		ad++;
		bd++;
	}

	// add carries
	for (; i < al && c; i++) {
		(*ad)++;
		c = ((*ad) == 0);
		ad++;
	}

	if (c) {
		if (a->max_length <= a->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}

		*ad = 1;
		a->length++;
	}
	return RA_ERR_SUCCESS;
}

// a = a - b; (a > b)
int _BnSubR(struct RaBigNumber *a, struct RaBigNumber *b)
{
	int i;
	int c;
	bn_uint_t *ad;
	bn_uint_t *bd;
	uint64_t val;
	int al;
	int bl;

	ad = &a->data[0];
	bd = &b->data[0];
	al = a->length;
	bl = b->length;

	c = 0;
	for (i = 0; i < bl; i++) {
#if BN_WORD_BYTE == 8
		if (c == 0) {
			c = (*ad) < (*bd);
			val = (uint64_t)(*ad) - (*bd);
		}
		else {
			c = (*ad) <= (*bd);
			val = (uint64_t)(*ad) - (*bd) - 1;
		}
		*ad = val;
#else
		val = (uint64_t)(*ad) - (*bd) + c;
		*ad = (uint32_t)val;
		c = (int)(val >> 32);
#endif
		ad++;
		bd++;
	}

	// sub carries
	for (; i < al && c; i++) {
		c = ((*ad) == 0);
		(*ad)--;
		ad++;
	}

	if (i == al) {
		while ( a->length > 1 && (*(--ad)) == 0)
		{
			a->length--;
		}
	}
	return RA_ERR_SUCCESS;
}

static int _BnCmp(struct RaBigNumber *a, struct RaBigNumber *b)
{
	bn_uint_t *ad;
	bn_uint_t *bd;

	if (a->length > b->length)
		return 1;
	else if (a->length < b->length)
		return -1;

	ad = &a->data[a->length - 1];
	bd = &b->data[b->length - 1];

	for (; ad > a->data; ad--, bd--) {
		if ((*ad) != (*bd))
			break;
	}
	if ((*ad) > (*bd))
		return 1;
	else if ((*ad) < (*bd))
		return -1;
	return 0;
}
/*
// r = r * 2
static int _BnDoubleR(struct RaBigNumber *r)
{
	int i;
	int c;
	int s;
	bn_uint_t *rd;
	c = 0;

	rd = &r->data[0];

	for (i = 0; i < r->length; i++) {
		s = ((*rd) >> (BN_WORD_BIT-1)) & 1;
		*rd = ((*rd) << 1) + c;
		c = s;
		rd++;
	}
	if (c) {
		if (r->max_length <= r->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}

		*rd = 1;
		r->length++;
	}
	return RA_ERR_SUCCESS;
}
*/

// a = a + (uint)val;
static int _BnAddUInt(struct RaBigNumber *a, bn_uint_t val)
{
	int i;
	int c;
	bn_uint_t *ad;
	int al;

	al = a->length;
	ad = &a->data[0];
	*ad += val;

	c = ((*ad) < val);

	ad++;
	// add carries
	for (i = 1; i < al && c; i++) {
		*ad = (*ad) + 1;
		c = ((*ad) == 0);
		ad++;
	}

	if (i == al && c) {
		if (a->max_length <= a->length) {
			assert(0);
			return RA_ERR_NUMBER_SIZE;
		}

		*ad = 1;
		a->length++;
	}
	return RA_ERR_SUCCESS;
}

// a = a - (uint)val;
static int _BnSubUInt(struct RaBigNumber *a, bn_uint_t val)
{
	int i;
	int c;
	bn_uint_t *ad;
	int al;

	al = a->length;
	ad = &a->data[0];

	if (al == 1 && (*ad) < val) {
		*ad = val - (*ad);
		a->sign = -a->sign;
		return RA_ERR_SUCCESS;
	}

	c = ((*ad) < val);
	(*ad) = (*ad) - val;

	ad++;
	// sub carries
	for (i = 1; i < al && c; i++) {
		c = ((*ad) == 0);
		*ad = (*ad) - 1;
		ad++;
	}

	if (i == al && a->length > 1 && (*--ad) == 0) {
		a->length--;
	}
	return RA_ERR_SUCCESS;
}


#if BN_WORD_BYTE == 8
#if defined(_MSC_VER) && defined(_M_X64)
#   pragma intrinsic(_umul128)
#if _MSC_VER > 1920		// Visual Studio 2019
#   pragma intrinsic(_udiv128)
#endif
#endif

static void _BnMul128(bn_uint128_t *r, uint64_t a, uint64_t b)
{
#if defined(__SIZEOF_INT128__)
	__uint128_t r128 = (__uint128_t)a * b;
	r->high = (uint64_t)(r128 >> 64);
	r->low = (uint64_t)r128;
#elif defined(_MSC_VER) && defined(_M_X64)
	r->low = _umul128(a, b, &r->high);
#else
	uint64_t al, ah;
	uint64_t bl, bh;
	uint64_t t1, t2;
	uint64_t r1, r2;

	al = a & 0xffffffff;
	ah = a >> 32;
	bl = b & 0xffffffff;
	bh = b >> 32;

	r1 = al * bl;
	r2 = ah * bh;

	t1 = bl * ah;
	t2 = bh * al;

	t2 += r1 >> 32;
	t2 += t1;
	// carry
	if (t2 < t1)
		r2 += UINT64_C(0x100000000);
	r->low = (r1 & 0xffffffff) + (t2 << 32);
	r->high = r2 + (t2 >> 32);
#endif
}

static uint64_t _BnDiv128(bn_uint128_t a, uint64_t b, uint64_t *remainder)
{
#if defined(__SIZEOF_INT128__)
	__uint128_t a128;
	if (a.high >= b) {
		// overflow
		return UINT64_C(0xFFFFFFFFFFFFFFFF);
	}
	a128 = ((__uint128_t)a.high << 64) | a.low;

	if (remainder != NULL)
		*remainder = (uint64_t)(a128 % b);
	return (uint64_t)(a128 / b);
#elif _MSC_VER > 1920 && defined(_M_X64)
	uint64_t r = 0;
	uint64_t q;
	if (a.high >= b) {
		// overflow
		return UINT64_C(0xFFFFFFFFFFFFFFFF);
	}
	q = _udiv128(a.high, a.low, b, &r);
	if (remainder != NULL)
		*remainder = r;
	return q;
#else
	bn_uint128_t r;
	uint64_t q;
	uint32_t qu;
	uint32_t bu;
	uint64_t ru;
	bn_uint128_t bq;
	int bit;

	q = 0;

	// make (ru / bu) fit to 32bit integer (ru = highst 64bit of r, bu = highst 32bit of bb)
	// so we calculate (a<<n)/(b<<n) instead of a/b
	bit = BN_WORD_BIT - 1 - _BnGetMSBPos64(b);
	b <<= bit;
	a.high = a.high << bit;
	// if bit is zero, (a.low >> BN_WORD_BIT) is not zero but a.low
	if (bit > 0)
		a.high |= a.low >> (BN_WORD_BIT - bit);
	a.low <<= bit;

	bu = (uint32_t)(b >> 32);

	r.high = a.high >> 32;
	r.low = (a.high << 32) | (a.low >> 32);

	ru = a.high;
	if (ru >= bu) {
		if ((ru >> 32) == bu)
			qu = 0xFFFFFFFF;
		else
			qu = (uint32_t)(ru / bu);
		
		_BnMul128(&bq, b, qu);	// bq = b * qu
		
		while (r.high < bq.high || (r.high == bq.high && r.low < bq.low)) {
			if (bq.low < b)
				bq.high--;
			bq.low -= b;
			qu--;
		}

		r.high -= bq.high;
		if (r.low < bq.low)
			r.high--;
		r.low -= bq.low;

		q = (uint64_t)qu << 32;
	}

	// r.high must be zero
	ru = r.low;
	// shift left 32bit
	r.high = r.low >> 32;
	r.low = (r.low << 32) | (a.low & 0xFFFFFFFF);
	if (ru >= bu) {
		if ((ru >> 32) == bu)
			qu = 0xFFFFFFFF;
		else
			qu = (uint32_t)(ru / bu);

		_BnMul128(&bq, b, qu);	// bq = b * qu

		while (r.high < bq.high || (r.high == bq.high && r.low < bq.low)) {
			if (bq.low < b)
				bq.high--;
			bq.low -= b;
			qu--;
		}

		r.high -= bq.high;
		if (r.low < bq.low)
			r.high--;
		r.low -= bq.low;

		q += qu;
	}

	// if bit is zero, r.high is zero. so (r.high << BN_WORD_BIT) does nothing
	r.low = (r.high << (BN_WORD_BIT - bit)) | (r.low >> bit);

	//r.high = r.high >> bit;

	if (remainder != NULL)
		*remainder = r.low;

	return q;
#endif
}

/*
static void _BnAdd128(bn_uint128_t *r, bn_uint128_t a, uint64_t b)
{
	r->high = a.high;
	r->low = a.low + b;
	if (r->low < b)
		r->high++;
}

static void _BnSub128(bn_uint128_t *r, bn_uint128_t a, uint64_t b)
{
	r->high = a.high;
	r->low = a.low;
	if (r->low < b)
		r->high--;
	r->low -= b;
}
*/
#endif

static int _BnGetMSBPos32(uint32_t val)
{
	static const int POS[32] = {
		0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
		8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
	};
	val |= val >> 1;
	val |= val >> 2;
	val |= val >> 4;
	val |= val >> 8;
	val |= val >> 16;
	return POS[(uint32_t)(val * 0x07C4ACDDU) >> 27];
}

#if BN_WORD_BYTE == 8
static int _BnGetMSBPos64(uint64_t val)
{
	uint32_t val_h;
	val_h = (uint32_t)(val >> 32);
	if (val_h != 0)
		return _BnGetMSBPos32(val_h) + 32;
	return _BnGetMSBPos32((uint32_t)val);
}

int _BnGetMSBPos(bn_uint_t val)
{
	return _BnGetMSBPos64(val);
}
#else
int _BnGetMSBPos(bn_uint_t val)
{
	return _BnGetMSBPos32(val);
}
#endif


uint32_t _BnGetUInt32(struct RaBigNumber *bn)
{
	return (uint32_t)bn->data[0];
}

uint64_t _BnGetUInt64(struct RaBigNumber *bn)
{
#if BN_WORD_BYTE == 8
	return bn->data[0];
#else
	if ( bn->length == 1 )
		return bn->data[0];
	else
		return ((uint64_t)bn->data[1] << 32) | bn->data[0];
#endif
}

bn_uint_t _BnGetUInt(struct RaBigNumber *bn)
{
	return bn->data[0];
}

void _BnInvert(struct RaBigNumber *bn)
{
	bn->sign = !bn->sign;
}

//////////////////////////////////////////
