/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <stdio.h>

#include <limits.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

#ifdef _WIN32
#include <Windows.h>
#define snprintf _snprintf
#endif

#include <racrypt.h>

static int _BnAdd(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);
static int _BnSub(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);
static int _BnCmp(struct BigNumber *a, struct BigNumber *b);
//static int _BnDoubleR(struct BigNumber *r);
static int _BnAddUInt(struct BigNumber *a, uint32_t val);
static int _BnSubUInt(struct BigNumber *a, uint32_t val);

struct BigNumber * BnNewW(int length)
{
	struct BigNumber * bn;
	if (length <= 0)
		length = BN_WORD_LEN;		// default length
	else if (length < 2)
		length = 2;					// minimum length is 2 (64bit)
	bn = (struct BigNumber *)malloc(sizeof(struct BigNumber) + sizeof(uint32_t) * length);
	bn->data = (uint32_t*)(bn + 1);
	bn->data[0] = 0;
	bn->length = 1;
	bn->sign = 0;
	bn->max_length = length;
	return bn;
}

struct BigNumber * BnNew(int bit)
{
	int word;
	word = (bit + BN_WORD_BIT - 1) / BN_WORD_BIT;
	return BnNewW(word);
}

struct BigNumber * BnClone(struct BigNumber *bn)
{
	struct BigNumber *new_bn;

	new_bn = BnNewW(bn->max_length);
	if (new_bn != NULL)
		BnSet(new_bn, bn);
	return new_bn;
}

void BnFree(struct BigNumber * bn)
{
	free(bn);
}

void BnClearFree(struct BigNumber* bn)
{
	memset(bn, 0, sizeof(struct BigNumber) + sizeof(uint32_t) * bn->max_length);
	free(bn);
}

void BnSetInt(struct BigNumber *bn, int32_t value)
{
	if (value < 0)
	{
		bn->sign = 1;
		value = -value;
	}
	else
	{
		bn->sign = 0;
	}
	bn->data[0] = (uint32_t)value;
	bn->length = 1;
}

void BnSetInt64(struct BigNumber *bn, int64_t value)
{
	if (value < 0)
	{
		bn->sign = 1;
		value = -value;
	}
	else
	{
		bn->sign = 0;
	}
	bn->data[0] = (uint32_t)value;
	bn->data[1] = (uint32_t)(value >> 32);
	bn->length = 1 + (bn->data[1] != 0);
}

void BnSetUInt(struct BigNumber *bn, uint32_t value)
{
	bn->data[0] = value;
	bn->length = 1;
	bn->sign = 0;
}

void BnSetUInt64(struct BigNumber *bn, uint64_t value)
{
	bn->data[0] = (uint32_t)value;
	bn->data[1] = (uint32_t)(value >> 32);
	bn->length = 1 + (bn->data[1] != 0);
	bn->sign = 0;
}

int BnSet(struct BigNumber *bn, struct BigNumber *bn2)
{
	if (bn->max_length < bn2->length) {
		return BN_ERR_NUMBER_SIZE;
	}
	memcpy(bn->data, bn2->data, sizeof(uint32_t) * bn2->length);
	bn->length = bn2->length;
	bn->sign = bn2->sign;
	return BN_ERR_SUCCESS;
}

static int _BnSetByteArray(struct BigNumber *bn, const uint8_t *data, int len, int isSigned)
{
	int word;
	int byte;
	const uint8_t *d;
	uint32_t *bd;
	const uint8_t *end;

	if (len <= 0) {
		return BN_ERR_INVALID_PARAM;
	}

	d = &data[0];
	end = &data[len];

	if (isSigned) {
		bn->sign = d[0] >> 7;
		if ( d[0] == 0x00 || d[0] == 0xff )
		{
			while ( len > 1 && ( d[0] == data[0] || d[0] == data[0] ) ) {
				d++;
				len--;
			}
		}
	}
	else {
		bn->sign = 0;
		while ( len > 1 && d[0] == 0x00 ){
			d++;
			len--;
		}
	}

	word = (len + sizeof(uint32_t) - 1) / sizeof(uint32_t);
	byte = (len + sizeof(uint32_t) - 1) % sizeof(uint32_t);		// byte of highst word
	if (bn->max_length < word) {
		return BN_ERR_NUMBER_SIZE;
	}

	bn->length = word;

	bd = &bn->data[word-1];

	*bd = 0;
	if (bn->sign)
		*bd = ~*bd;

	switch(byte) {
	case 3:
		*bd = (*bd << 8 ) | *d++;
	case 2:
		*bd = (*bd << 8 ) | *d++;
	case 1:
		*bd = (*bd << 8 ) | *d++;
	case 0:
		*bd = (*bd << 8 ) | *d++;
	default:
		break;
	}
	if (bn->sign)
		*bd = ~*bd;

	bd--;

	while(d < end) {
		*bd = (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
		if (bn->sign)
			*bd = ~*bd;
		bd--;
		d += 4;
	}
	while( bn->length > 1 && bn->data[bn->length-1] == 0 ) {
		bn->length--;
	}
	if (bn->sign)
		BnSubInt(bn, 1);

	return BN_ERR_SUCCESS;
}

int BnSetByteArray(struct BigNumber *bn, const uint8_t *data, int len)
{
	return _BnSetByteArray(bn, data, len, 1);
}

int BnSetUByteArray(struct BigNumber *bn, const uint8_t *data, int len)
{
	return _BnSetByteArray(bn, data, len, 0);
}

// a < b : -1, a > b : 1, a = b : 0
int BnCmp(struct BigNumber *a, struct BigNumber *b)
{
	if (a->sign == 0)
	{
		if (b->sign == 0)
			return _BnCmp(a, b);
		else
			return 1;
	}
	else
	{
		if (b->sign == 0)
			return -1;
		else
			return -_BnCmp(a, b);
	}
}

int BnCmpInt(struct BigNumber *a, int32_t val)
{
	if (a->sign == 0)
	{
		if (a->length > 1 || val < 0)
			return 1;
		if (a->data[0] > (uint32_t)val)
			return 1;
		else if (a->data[0] < (uint32_t)val)
			return -1;
		return 0;
	}
	else
	{
		if (a->length > 1 || val > 0)
			return -1;
		val = -val;
		if (a->data[0] > (uint32_t)val)
			return -1;
		else if (a->data[0] < (uint32_t)val)
			return 1;
		return 0;
	}
}

int BnCmpUInt(struct BigNumber *a, uint32_t val)
{
	if (a->sign == 0)
	{
		if (a->length > 1)
			return 1;
		if (a->data[0] > val)
			return 1;
		else if (a->data[0] < val)
			return -1;
		return 0;
	}
	else
	{
		if (a->data[0] == 0)
			return 0;
		return -1;
	}
}

int BnAdd(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	int ret;
	if (a->sign ^ b->sign)
	{
		if (_BnCmp(a, b) > 0)
		{
			ret = _BnSub(r, a, b);
			r->sign = a->sign;
		}
		else
		{
			ret = _BnSub(r, b, a);
			r->sign = b->sign;
		}
	}
	else
	{
		ret = _BnAdd(r, a, b);
		r->sign = a->sign;
	}
	return ret;
}

// r = a - b
int BnSub(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	int ret;
	if (a->sign ^ b->sign)
	{
		ret = _BnAdd(r, a, b);
		r->sign = a->sign;
	}
	else
	{
		if (_BnCmp(a, b) > 0)
		{
			ret = _BnSub(r, a, b);
			r->sign = a->sign;
		}
		else
		{
			ret = _BnSub(r, b, a);
			r->sign = !a->sign;
		}
	}
	return ret;
}


int BnDouble(struct BigNumber *r, struct BigNumber *a)
{
	int i;
	int c;
	uint32_t *rd;
	uint32_t *ad;

	if (r->max_length < a->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}

	c = 0;
	rd = &r->data[0];
	ad = &a->data[0];
	r->length = a->length;
	for (i = 0; i < a->length; i++)
	{
		*rd = ((*ad) << 1) + c;
		c = ((*ad) >> 31) & 1;
		ad++;
		rd++;
	}
	if (c)
	{
		if (r->max_length <= r->length) {
			assert(0);
			return BN_ERR_NUMBER_SIZE;
		}

		*rd = 1;
		r->length++;
	}
	r->sign = a->sign;
	return BN_ERR_SUCCESS;
}

int BnMul(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	uint64_t val;
	int c;
	int i, j;
	int length;
	uint32_t *ad;
	uint32_t *bd;
	uint32_t *rd;

	if (BN_ISZERO(a) || BN_ISZERO(b))
	{
		BnSetUInt(r, 0);
		return BN_ERR_SUCCESS;
	}
	length = a->length + b->length;
	if (r->max_length < length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}

	memset(r->data, 0, sizeof(uint32_t) * length);

	rd = r->data;
	for (i = 0; i < b->length; i++)
	{
		val = 0;
		c = 0;

		ad = &a->data[0];
		bd = &b->data[i];
		rd = &r->data[i];

		for (j = 0; j < a->length; j++)
		{
			val = (uint64_t)(*ad) * (*bd) + (val >> 32) + c;
			*rd += (uint32_t)val;
			c = ((*rd) < (uint32_t)val);
			rd++;
			ad++;
		}
		val >>= 32;
		if (val > 0)
		{
			val = (uint64_t)(*rd) + val + c;
			*rd = (uint32_t)val;
			c = (int)(val >> 32);
			rd++;
		}
		while (c)
		{
			*rd += c;
			c = ( (*rd) == 0 );
			rd++;
		}
	}

	r->length = (int)(intptr_t)(rd - r->data);;
	r->sign = a->sign ^ b->sign;
	return BN_ERR_SUCCESS;
}

int BnSqr(struct BigNumber *r, struct BigNumber *a)
{
	uint64_t val;
	int c;
	int i, j;
	int length;
	uint32_t *ad;
	uint32_t *bd;
	uint32_t *rd;

	if (BN_ISZERO(a) || BN_ISONE(a)) {
		BnSet(r, a);
		return BN_ERR_SUCCESS;
	}

	length = a->length * 2;
	if (r->max_length < length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}

	memset(r->data, 0, sizeof(uint32_t) * length);

	rd = r->data;
	for (i = 0; i < a->length; i++)
	{
		val = 0;
		c = 0;

		ad = &a->data[0];
		bd = &a->data[i];
		rd = &r->data[i];

		for (j = 0; j < a->length; j++)
		{
			val = (uint64_t)(*ad) * (*bd) + (val >> 32) + c;
			*rd += (uint32_t)val;
			c = ((*rd) < (uint32_t)val);
			rd++;
			ad++;
		}
		val >>= 32;
		if (val > 0)
		{
			val = (uint64_t)(*rd) + val + c;
			*rd = (uint32_t)val;
			c = (int)(val >> 32);
			rd++;
		}
		while (c)
		{
			*rd += c;
			c = ((*rd) == 0);
			rd++;
		}
	}
	r->length = (int)(intptr_t)(rd - r->data);
	r->sign = 0;

	return BN_ERR_SUCCESS;
}

// r = a % b
int BnMod(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	struct BigNumber *aa;		// a << n
	struct BigNumber *bb;		// b << n
	struct BigNumber *bq;		// b * q
	int bit;
	uint32_t qu;
	uint64_t ru;
	uint32_t bu;
	uint32_t* ad;
	uint32_t* rd;

	if (r->max_length < b->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}
	// divide by zero
	if (BN_ISZERO(b)) {
		assert(0);
		return BN_ERR_DIVIDED_BY_ZERO;
	}
	if (a->length < b->length)
	{
		BnSet(r, a);
		return BN_ERR_SUCCESS;
	}

	aa = BnNewW(a->length + 1);		// a << n
	bb = BnNewW(b->length + 1);		// b << n
	bq = BnNewW(b->length + 1);		// b * qu(32bit)

	if (aa == NULL || bb == NULL || bq == NULL)
	{
		BN_SAFEFREE(aa);
		BN_SAFEFREE(bb);
		BN_SAFEFREE(bq);
		return BN_ERR_OUT_OF_MEMORY;
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
	if (b->length > 1)
	{
		memcpy(r->data, aa->data + aa->length - bb->length + 1, sizeof(uint32_t) * (bb->length - 1));
		r->data[bb->length] = 0;
		r->length = bb->length - 1;
	}

	bu = bb->data[bb->length - 1];		// highst 32bit of bb
	ad = &aa->data[aa->length - bb->length];
	rd = &r->data[bb->length - 1];

	ru = 0;

	while (ad >= aa->data)
	{
		BnShiftL(r, 32);
		r->data[0] = (*ad);

		// check the length
		if (r->length > b->length)
			ru = ((uint64_t)(*(rd + 1)) << 32) | (*rd);
		else if (r->length == b->length)
			ru = *rd;
		else
			ru = 0;

		if (ru >= bu)
		{
			if (*(rd + 1) == bu)		// overflow
				qu = 0xFFFFFFFF;
			else
				qu = (uint32_t)(ru / bu);		// guess the quotient

			BnSet(bq, bb);
			BnMulUInt(bq, qu);		// bq = bb * qu
			while (_BnCmp(r, bq) < 0)
			{
				_BnSubR(bq, bb);
				qu--;
			}
			if (qu > 0)
			{
				_BnSubR(r, bq);		// rr -= bb * qu
			}
		}
		else
		{
			qu = 0;
		}

		ad--;
	}

	BnShiftR(r, (uint32_t)bit);
	r->sign = a->sign;

	BnFree(aa);
	BnFree(bb);
	BnFree(bq);

	return BN_ERR_SUCCESS;
}

int BnDiv(struct BigNumber *q, struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	struct BigNumber *rr;
	struct BigNumber *aa;		// a << n
	struct BigNumber *bb;		// b << n
	struct BigNumber *bq;		// b * q
	int bit;
	int length;
	uint32_t qu;
	uint64_t ru;
	uint32_t bu;
	uint32_t* ad;
	uint32_t* qd;
	uint32_t* rd;

	if (r->max_length < b->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}

	if (q->max_length <= a->length - b->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}

	// divide by zero
	if (BN_ISZERO(b)) {
		assert(0);
		return BN_ERR_DIVIDED_BY_ZERO;
	}

	if (a->length < b->length)
	{
		BnSet(r, a);
		BnSetInt(q, 0);
		return BN_ERR_SUCCESS;
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
		return BN_ERR_OUT_OF_MEMORY;
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
	if(b->length > 1)
	{
		memcpy(rr->data, aa->data + aa->length - bb->length + 1, sizeof(uint32_t) * (bb->length - 1));
		rr->data[bb->length] = 0;
		rr->length = bb->length - 1;
	}

	bu = bb->data[bb->length - 1];		// highst 32bit of bb
	qd = &q->data[aa->length - bb->length];
	ad = &aa->data[aa->length - bb->length];
	rd = &rr->data[bb->length - 1];

	ru = 0;
	length = 0;
	while (ad >= aa->data)
	{
		BnShiftL(rr, 32);
		rr->data[0] = (*ad);

		if ( rr->length > bb->length )
			ru = ((uint64_t)(*(rd + 1)) << 32) | (*rd);
		else if ( rr->length == bb->length )
			ru = *rd;
		else
			ru = 0;

		if (ru >= bu)
		{
			if  (*(rd + 1) == bu)		// overflow
				qu = 0xFFFFFFFF;
			else
				qu = (uint32_t)(ru / bu);		// guess the quotient

			BnSet(bq, bb);
			BnMulUInt(bq, qu);		// bq = bb * qu
			while (_BnCmp(rr, bq) < 0)
			{
				_BnSubR(bq, bb);
				qu--;
			}
			if (qu > 0)
			{
				_BnSubR(rr, bq);		// rr -= bb * qu
				if (length == 0)
				{
					length = (int)(intptr_t)(qd - q->data) + 1;
				}
			}
		}
		else
		{
				qu = 0;
		}
		if (length > 0) {
			*qd = qu;
		}
		qd--;
		ad--;
	}

	q->length = length;
	if (q->length == 0) {
		q->length = 1;
		q->data[0] = 0;
	}
	q->sign = a->sign ^ b->sign;

	BnShiftR(rr, (uint32_t)bit);
	rr->sign = a->sign;
	BnSet(r, rr);

	BnFree(aa);
	BnFree(bb);
	BnFree(bq);
	BnFree(rr);

	return BN_ERR_SUCCESS;
}


int BnAddInt(struct BigNumber *bn, int32_t val)
{
	int ret;
	if (val > 0)
	{
		if (bn->sign == 0)
			ret = _BnAddUInt(bn, (uint32_t)val);
		else
			ret = _BnSubUInt(bn, (uint32_t)val);
	}
	else
	{
		if (bn->sign == 0)
			ret = _BnSubUInt(bn, (uint32_t)-val);
		else
			ret = _BnAddUInt(bn, (uint32_t)-val);
	}
	return ret;
}

int BnAddUInt(struct BigNumber *bn, uint32_t val)
{
	int ret;
	if (bn->sign == 0)
		ret = _BnAddUInt(bn, val);
	else
		ret = _BnSubUInt(bn, val);
	return ret;
}

int BnSubInt(struct BigNumber *bn, int32_t val)
{
	int ret;
	if (val > 0)
	{
		if (bn->sign == 0)
			ret = _BnSubUInt(bn, (uint32_t)val);
		else
			ret = _BnAddUInt(bn, (uint32_t)val);
	}
	else
	{
		if (bn->sign == 0)
			ret = _BnAddUInt(bn, (uint32_t)-val);
		else
			ret = _BnSubUInt(bn, (uint32_t)-val);
	}
	return ret;
}

int BnSubUInt(struct BigNumber *bn, uint32_t val)
{
	int ret;
	if ( bn->sign == 0 )
		ret = _BnSubUInt( bn, val );
	else
		ret = _BnAddUInt( bn, val );
	return ret;
}

int BnMulInt(struct BigNumber *bn, int32_t multiplier)
{
	uint64_t val;
	int i;

	if (multiplier < 0)
	{
		bn->sign = -bn->sign;
		multiplier = -multiplier;
	}
	val = 0;
	for (i = 0; i < bn->length; i++)
	{
		val = (uint64_t)bn->data[i] * (uint32_t)multiplier + (val >> 32);
		bn->data[i] = (uint32_t)val;
	}
	val >>= 32;
	if (val > 0)
	{
		if (bn->max_length <= bn->length) {
			assert(0);
			return BN_ERR_NUMBER_SIZE;
		}
		bn->data[bn->length] = (uint32_t)val;
		bn->length++;
	}
	return BN_ERR_SUCCESS;
}

int BnMulUInt(struct BigNumber *bn, uint32_t multiplier)
{
	uint64_t val;
	int i;

	val = 0;
	for (i = 0; i < bn->length; i++)
	{
		val = (uint64_t)bn->data[i] * (uint32_t)multiplier + (val >> 32);
		bn->data[i] = (uint32_t)val;
	}
	val >>= 32;
	if (val > 0)
	{
		if (bn->max_length <= bn->length) {
			assert(0);
			return BN_ERR_NUMBER_SIZE;
		}
		bn->data[bn->length] = (uint32_t)val;
		bn->length++;
	}
	return BN_ERR_SUCCESS;
}

int BnDivInt(struct BigNumber *bn, int32_t divisor, /*out*/uint32_t *remainder)
{
	uint64_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return BN_ERR_DIVIDED_BY_ZERO;
	}
	if (divisor < 0)
	{
		bn->sign = -bn->sign;
		divisor = -divisor;
	}
	val = 0;
	for (i = bn->length - 1; i >= 0; i--)
	{
		val = (val << 32) + bn->data[i];
		if (val > divisor)
		{
			if (length == 0)
				length = i + 1;
			bn->data[i] = (uint32_t)(val / (uint32_t)divisor);
			val %= (uint32_t)divisor;
		}
		else
		{
			bn->data[i] = 0;
		}
	}
	if (length == 0)
	{
		bn->length = 1;
		bn->data[0] = 0;
	}
	else
	{
		bn->length = length;
	}

	if (remainder != NULL)
		*remainder = (uint32_t)val;

	return BN_ERR_SUCCESS;
}

int BnDivUInt(struct BigNumber *bn, uint32_t divisor, /*out*/uint32_t *remainder)
{
	uint64_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return BN_ERR_DIVIDED_BY_ZERO;
	}
	val = 0;
	for (i = bn->length - 1; i >= 0; i--)
	{
		val = (val << 32) + bn->data[i];
		if (val > divisor)
		{
			if (length == 0)
				length = i + 1;
			bn->data[i] = (uint32_t)(val / (uint32_t)divisor);
			val %= (uint32_t)divisor;
		}
		else
		{
			bn->data[i] = 0;
		}
	}
	if (length == 0)
	{
		bn->length = 1;
		bn->data[0] = 0;
	}
	else
	{
		bn->length = length;
	}

	if (remainder != NULL) {
		*remainder = (uint32_t)val;
	}
	return BN_ERR_SUCCESS;
}

int BnModUInt(struct BigNumber *bn, uint32_t divisor, /*out*/uint32_t *remainder)
{
	uint64_t val;
	int i;
	int length = 0;

	if (divisor == 0) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}
	val = 0;
	for (i = bn->length - 1; i >= 0; i--)
	{
		val = (val << 32) + bn->data[i];
		if (val > divisor)
		{
			if (length == 0)
				length = i + 1;
			val %= (uint32_t)divisor;
		}
	}

	*remainder = (uint32_t)val;
	return BN_ERR_SUCCESS;
}

/////////////////////////////////////////////

int BnShiftL(struct BigNumber *bn, uint32_t bit)

{
	int word;
	uint32_t* dest;
	uint32_t* src;
	uint32_t val;
	uint32_t val_prev;

	if (bit == 0) {
		return BN_ERR_SUCCESS;
	}

	word = (bit + BN_WORD_BIT - 1) / BN_WORD_BIT;
	bit %= BN_WORD_BIT;

	if (bn->max_length < bn->length + word) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
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

	return BN_ERR_SUCCESS;
}

int BnShiftR(struct BigNumber *bn, uint32_t bit)
{
	int word;
	uint32_t* dest;
	uint32_t* src;
	uint32_t* bn_end;
	uint32_t val;
	uint32_t val_prev;

	if (bit == 0) {
		return BN_ERR_SUCCESS;
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
			*dest = ( val_prev >> bit ) | ( val << ( BN_WORD_BIT - bit ) );
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

	return BN_ERR_SUCCESS;
}

int BnGetMaxLength(struct BigNumber *bn)
{
	return bn->max_length;
}

int BnGetLength(struct BigNumber *bn)
{
	return bn->length;
}

int BnGetBitLength(struct BigNumber *bn)
{
	int bit;
	bit = (bn->length - 1) * BN_WORD_BIT;
	bit += _BnGetMSBPos(bn->data[bn->length - 1]) + 1;
	return bit;
}
/////////////////////////////////////////////

static uint16_t _rand16(uint32_t *seedp)
{
	*seedp = ((*seedp * 1103515245) + 12345) & 0x7fffffff;
	return (uint16_t)(*seedp >> 15);
}
static uint32_t _rand32(uint32_t *seedp)
{
	return _rand16(seedp) | ((uint32_t)_rand16(seedp) << 16);
}

int BnGenRandom(struct BigNumber *bn, int bit, uint32_t *seedp)
{
	uint32_t seed;
	int word;
	int i;

	if (seedp != NULL && *seedp != 0) {
		seed = *seedp;
	}
	else {
#ifdef _WIN32
		seed = GetTickCount();
#else
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		seed = (uint32_t) ts.tv_nsec;
#endif
	}
	if (bit <= 0) {
		BnSetInt(bn, 0);
		return BN_ERR_SUCCESS;
	}
	_rand32(&seed);

	word = (bit + BN_WORD_BIT - 1) / BN_WORD_BIT;
	if (bn->max_length < word) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}

	for (i = 0; i < word; i++) {
		bn->data[i] = _rand32(&seed);
	}
	bit %= BN_WORD_BIT;

	if (bit > 0) {
		bn->data[word - 1] &= (1 << bit) - 1;
	}
	bn->length = word;
	while (bn->length > 1 && bn->data[bn->length - 1] == 0)
		bn->length--;
	if (seedp != NULL)
		*seedp = seed;
	return BN_ERR_SUCCESS;
}

int BnGetRandomOdd(struct BigNumber *bn, int bit, uint32_t *seedp)
{
	int ret;

	ret = BnGenRandom(bn, bit, seedp);
	if (ret != BN_ERR_SUCCESS)
		return ret;

	bn->data[0] |= 1;
	return BN_ERR_SUCCESS;
}

int BnGetRandomRSA(struct BigNumber *bn, int bit, uint32_t *seedp)
{
	int ret;
	int word;

	ret = BnGenRandom(bn, bit, seedp);
	if (ret != BN_ERR_SUCCESS)
		return ret;

	bn->data[0] |= 1;
	word = (bit + BN_WORD_BIT - 1) / BN_WORD_BIT;
	bit = ((bit - 1) % BN_WORD_BIT);
	bn->data[word - 1] |= 1 << bit;
	bn->length = word;
	return BN_ERR_SUCCESS;
}

/////////////////////////////////////////////
int BnToByteArray(struct BigNumber *bn, uint8_t *buffer, int bufferlen)
{
	int i;
	int offset;
	int bit;
	int len;
	uint32_t word;

	offset = 0;
	if (bn->sign && !BN_ISZERO(bn)) {
		struct BigNumber *neg;
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
		len = offset + (bit / 8 + 1) + (neg->length - 1) * 4;
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
			bit = 24;
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
		len = offset + (bit / 8 + 1) + (bn->length - 1) * 4;
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
			bit = 24;
		}

		return offset;
	}
}

int BnToFixedByteArray( struct BigNumber *bn, uint8_t *buffer, int bufferlen )
{
	int i;
	int offset;
	int bit;
	int len;
	uint32_t word;

	// positive value only
	if ( bn->sign && !BN_ISZERO( bn ) )
	{
		return 0;
	}
	word = bn->data[bn->length - 1];
	bit = _BnGetMSBPos( word );

	len = ( bit / 8 + 1 ) + ( bn->length - 1 ) * 4;
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
		bit = 24;
	}

	return offset;
}

void BnPrint(struct BigNumber *bn)
{
	int i;

	if (bn->sign && !BN_ISZERO(bn))
		printf("-");

	for (i = bn->length - 1; i >= 0; i--) {
		printf("%08x", bn->data[i]);
	}
}

void BnPrintLn(struct BigNumber *bn)
{
	BnPrint(bn);
	printf("\n");
}

int BnSPrint(struct BigNumber *bn, char *buffer, int bufferlen)
{
	int i;
	int offset;
	assert(bufferlen >= (bn->length * 8 + 1));

	offset = 0;
	if (bn->sign && !BN_ISZERO(bn)) {
		assert(bufferlen >= (bn->length * 8 + 2));
        if (buffer != NULL && bufferlen > 1)
		    buffer[0] = '-';
		offset++;
	}
    if (buffer == NULL) {
        return bn->length * 8 + offset + 1;
    }

    if (bufferlen < bn->length * 8 + offset + 1) {
        return BN_ERR_OUT_OF_BUFFER;
    }

	for (i = bn->length - 1; i >= 0; i--)
	{
		snprintf(buffer + offset, (size_t)(bufferlen - offset), "%08x", bn->data[i]);
		offset += 8;
	}
	buffer[offset] = '\0';

    return offset;
}

// max_dec_digit = log10(16^max_hex_digit) = max_hex_digit * log10(16)
// max_dec_word = max_dec_digit / 9		(needed one word for 9 digit)
#define BN_MAX_DEC_LEN(word_len)		(int)((word_len)*8*1.204120 / 9 + 1)		// 1.204120 = log10(16)

void BnPrint10(struct BigNumber *bn)
{
	struct BigNumber * bn2;
	uint32_t* decimal;
	int i;

	decimal = malloc(sizeof(uint32_t) * BN_MAX_DEC_LEN(bn->length));
	bn2 = BnClone(bn);
    if (decimal == NULL || bn2 == NULL) {
        printf("<mem alloc error>\n");
        goto _EXIT;
    }

	i = 0;
	do {
		BnDivInt(bn2, 1000000000, &decimal[i++]);
	} while (!BN_ISZERO(bn2));

	i--;

	if (bn->sign && !BN_ISZERO(bn))
		printf("-");

	printf("%u", decimal[i]);
	while (--i >= 0) {
		printf("%09u", decimal[i]);
	}

_EXIT:
	BN_SAFEFREE(bn2);
    if (decimal != NULL)
	    free(decimal);
}

void BnPrint10Ln(struct BigNumber *bn)
{
	BnPrint10(bn);
	printf("\n");
}

int BnSPrint10(struct BigNumber *bn, char *buffer, int bufferlen)
{
    int result;
	struct BigNumber * bn2;
	uint32_t* decimal;
	int i;
	int offset;
    char temp[11];

	decimal = malloc(sizeof(uint32_t) * BN_MAX_DEC_LEN(bn->length));
	bn2 = BnClone(bn);
    if (decimal == NULL || bn2 == NULL) {
        result = BN_ERR_OUT_OF_MEMORY;
        goto _EXIT;
    }

	i = 0;
	do {
		BnDivInt(bn2, 1000000000, &decimal[i++]);
	} while (!BN_ISZERO(bn2));

	i--;

	offset = 0;
	if (bn->sign && !BN_ISZERO(bn)) {
        temp[0] = '-';
		offset++;
	}

    snprintf(temp, sizeof(temp), "%u", decimal[i]);
	offset = (int)strlen(temp);

	if (bufferlen < offset + i * 9 + 1) {
        assert(0);
        result = BN_ERR_OUT_OF_BUFFER;
        goto _EXIT;
    }
    strncpy(buffer, temp, (size_t)offset);

	while (--i >= 0) {
		snprintf(buffer + offset, (size_t)bufferlen - offset, "%09u", decimal[i]);
		offset += 9;
	}
    buffer[offset] = '\0';

    result = BN_ERR_SUCCESS;

_EXIT:
  	BN_SAFEFREE(bn2);
    if (decimal != NULL)
        free(decimal);

    return result;
}

//////////////////////////////////////////////
// unsigned internal functions
static int _BnAdd(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	int i;
	int c;
	uint32_t *ad;
	uint32_t *bd;
	uint32_t *rd;
	uint64_t val;
	int al;
	int bl;

	if (r->max_length < a->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}
	if (a->length > b->length)
	{
		ad = &a->data[0];
		bd = &b->data[0];
		al = a->length;
		bl = b->length;
	}
	else
	{
		ad = &b->data[0];
		bd = &a->data[0];
		al = b->length;
		bl = a->length;
	}

	r->length = al;
	rd = &r->data[0];
	c = 0;
	for (i = 0; i < bl; i++)
	{
		val = (uint64_t)(*ad) + (*bd) + c;
		*rd = (uint32_t)val;
		c = (int)(val >> 32);
		rd++;
		ad++;
		bd++;
	}

	// add carries
	for (; i < al && c; i++)
	{
		*rd = (*ad) + 1;
		c = ((*rd) == 0);
		rd++;
		ad++;
	}

	for (; i < al; i++)
	{
		*rd = (*ad);
		rd++;
		ad++;
	}

	if (c)
	{
		if (r->max_length <= r->length) {
			assert(0);
			return BN_ERR_NUMBER_SIZE;
		}

		*rd = 1;
		r->length++;
	}
	return BN_ERR_SUCCESS;
}

// r = a - b (a > b)
static int _BnSub(struct BigNumber *r, struct BigNumber *a, struct BigNumber *b)
{
	int i;
	int c;
	uint32_t *ad;
	uint32_t *bd;
	uint32_t *rd;
	uint64_t val;
	int al;
	int bl;

	ad = &a->data[0];
	bd = &b->data[0];
	al = a->length;
	bl = b->length;
	if (a->length < b->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}
	if (r->max_length < a->length) {
		assert(0);
		return BN_ERR_NUMBER_SIZE;
	}
	r->length = al;
	rd = &r->data[0];
	c = 0;
	for (i = 0; i < bl; i++)
	{
		val = (uint64_t)(*ad) - (*bd) + c;
		*rd = (uint32_t)val;
		c = (int)(val >> 32);
		rd++;
		ad++;
		bd++;
	}

	// sub carries
	for (; i < al && c; i++)
	{
		c = ((*ad) == 0);
		*rd = (*ad) - 1;
		rd++;
		ad++;
	}

	for (; i < al; i++)
	{
		*rd = (*ad);
		rd++;
		ad++;
	}

	while (r->length > 1 && (*(--rd)) == 0)
	{
		r->length--;
	}
	return BN_ERR_SUCCESS;
}

// a = a + b
int _BnAddR(struct BigNumber *a, struct BigNumber *b)
{
	int i;
	int c;
	uint32_t *ad;
	uint32_t *bd;
	uint64_t val;
	int al;
	int bl;

	ad = &a->data[0];
	bd = &b->data[0];
	al = a->length;
	bl = b->length;

	if (a->length < b->length)
	{
		memset(a->data + a->length, 0, sizeof(uint32_t) * (b->length - a->length));
		a->length = b->length;
	}
	c = 0;
	for (i = 0; i < bl; i++)
	{
		val = (uint64_t)(*ad) + (*bd) + c;
		*ad = (uint32_t)val;
		c = (int)(val >> 32);
		ad++;
		bd++;
	}

	// add carries
	for (; i < al && c; i++)
	{
		(*ad)++;
		c = ((*ad) == 0);
		ad++;
	}

	if (c)
	{
		if (a->max_length <= a->length) {
			assert(0);
			return BN_ERR_NUMBER_SIZE;
		}

		*ad = 1;
		a->length++;
	}
	return BN_ERR_SUCCESS;
}

// a = a - b; (a > b)
int _BnSubR(struct BigNumber *a, struct BigNumber *b)
{
	int i;
	int c;
	uint32_t *ad;
	uint32_t *bd;
	uint64_t val;
	int al;
	int bl;

	ad = &a->data[0];
	bd = &b->data[0];
	al = a->length;
	bl = b->length;

	c = 0;
	for (i = 0; i < bl; i++)
	{
		val = (uint64_t)(*ad) - (*bd) + c;
		*ad = (uint32_t)val;
		c = (int)(val >> 32);

		ad++;
		bd++;
	}

	// sub carries
	for (; i < al && c; i++)
	{
		c = ((*ad) == 0);
		(*ad)--;
		ad++;
	}

	if (i == al)
	{
		while ( a->length > 1 && (*(--ad)) == 0)
		{
			a->length--;
		}
	}
	return BN_ERR_SUCCESS;
}

static int _BnCmp(struct BigNumber *a, struct BigNumber *b)
{
	uint32_t *ad;
	uint32_t *bd;

	if (a->length > b->length)
		return 1;
	else if (a->length < b->length)
		return -1;

	ad = &a->data[a->length - 1];
	bd = &b->data[b->length - 1];

	for (; ad > a->data; ad--, bd--)
	{
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
static int _BnDoubleR(struct BigNumber *r)
{
	int i;
	int c;
	int s;
	uint32_t *rd;
	c = 0;

	rd = &r->data[0];

	for (i = 0; i < r->length; i++)
	{
		s = ((*rd) >> 31) & 1;
		*rd = ((*rd) << 1) + c;
		c = s;
		rd++;
	}
	if (c)
	{
		if (r->max_length <= r->length) {
			assert(0);
			return BN_ERR_NUMBER_SIZE;
		}

		*rd = 1;
		r->length++;
	}
	return BN_ERR_SUCCESS;
}
*/

// a = a + (uint)val;
static int _BnAddUInt(struct BigNumber *a, uint32_t val)
{
	int i;
	int c;
	uint32_t *ad;
	int al;

	al = a->length;
	ad = &a->data[0];
	*ad += val;

	c = ((*ad) < val);

	ad++;
	// add carries
	for (i = 1; i < al && c; i++)
	{
		*ad = (*ad) + 1;
		c = ((*ad) == 0);
		ad++;
	}

	if (i == al && c)
	{
		if (a->max_length <= a->length) {
			assert(0);
			return BN_ERR_NUMBER_SIZE;
		}

		*ad = 1;
		a->length++;
	}
	return BN_ERR_SUCCESS;
}

// a = a - (uint)val;
static int _BnSubUInt(struct BigNumber *a, uint32_t val)
{
	int i;
	int c;
	uint32_t *ad;
	int al;

	al = a->length;
	ad = &a->data[0];

	if (al == 1 && (*ad) < val)
	{
		*ad = val - (*ad);
		a->sign = -a->sign;
		return BN_ERR_SUCCESS;
	}

	c = ((*ad) < val);
	(*ad) = (*ad) - val;

	ad++;
	// sub carries
	for (i = 1; i < al && c; i++)
	{
		c = ((*ad) == 0);
		*ad = (*ad) - 1;
		ad++;
	}

	if (i == al && a->length > 1 && (*--ad) == 0)
	{
		a->length--;
	}
	return BN_ERR_SUCCESS;
}

int _BnGetMSBPos(uint32_t val)
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

uint32_t _BnGetUInt32(struct BigNumber *bn)
{
	return bn->data[0];
}

uint64_t _BnGetUInt64(struct BigNumber *bn)
{
	if ( bn->length == 1 )
		return bn->data[0];
	else
		return ((uint64_t)bn->data[1] << 32) | bn->data[0];
}

void _BnInvert(struct BigNumber *bn)
{
	bn->sign = !bn->sign;
}

//////////////////////////////////////////
