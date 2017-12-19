/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <racrypt.h>

// r = gcd(m,n)
// Euclidean algorithm
int GetGCD(/*out*/struct BigNumber *r, struct BigNumber *m, struct BigNumber *n)
{
	int result;
	struct BigNumber *r1;
	struct BigNumber *r2;

	if (BN_ISZERO(m) || BN_ISZERO(n)) {
		assert(0);
		return BN_ERR_DIVIDED_BY_ZERO;
	}

	r1 = BnNewW(BnGetLength(n));
	r2 = BnNewW(BnGetLength(n));
	if (r1 == NULL || r2 == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	for (;;)
	{
		// r1 = m / n
		result = BnMod(r1, m, n);
		if (result != BN_ERR_SUCCESS) goto _EXIT;

		m = n;
		n = r1;
		if (BnCmpUInt(r1, 0) == 0)
			break;
		// r2 = m / n
		result = BnMod(r2, m, n);
		if (result != BN_ERR_SUCCESS) goto _EXIT;

		m = n;
		n = r2;
		if (BnCmpUInt(r2, 0) == 0)
			break;
	}
	BnSet(r, m);

	result = BN_ERR_SUCCESS;
_EXIT:
	BN_SAFEFREE(r1);
	BN_SAFEFREE(r2);

	return result;
}

// r = gcd(m,n)
// gcd(m,n) = a*m + b*n
// Extended Euclidean algorithm
int GetGCDEx(/*out,nullable*/struct BigNumber *r, /*out*/struct BigNumber *a, /*out*/struct BigNumber *b, struct BigNumber *m, struct BigNumber *n, int isUnsigned)
{
	int result;
	struct BigNumber *r1 = NULL;
	struct BigNumber *r2 = NULL;
	struct BigNumber *q = NULL;
	struct BigNumber *m1;
	struct BigNumber *n1;
	struct BigNumber *st[7];
	struct BigNumber *s_2;		// s[k-2]
	struct BigNumber *s_1;		// s[k-1]
	struct BigNumber *s_0;		// s[k]
	struct BigNumber *t_2;		// t[k-2]
	struct BigNumber *t_1;		// t[k-1]
	struct BigNumber *t_0;		// t[k]
	struct BigNumber *tmp;
	struct BigNumber *swap;
	int i;

	if (BN_ISZERO(m) || BN_ISZERO(n)) {
		assert(0);
		return BN_ERR_DIVIDED_BY_ZERO;
	}
	memset(st, 0, sizeof(st));

	i = m->length > n->length ? m->length : n->length;

	r1 = BnNewW(i);
	r2 = BnNewW(i);
	q = BnNewW(i);
	if (r1 == NULL || r2 == NULL || q == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	for (i = 0; i < 7; i++)
	{
		st[i] = BnNewW(q->max_length * 2);
		if (st[i] == NULL) {
			result = BN_ERR_OUT_OF_MEMORY;
			goto _EXIT;
		}
	}

	s_2 = st[0];
	s_1 = st[1];
	s_0 = st[2];
	t_2 = st[3];
	t_1 = st[4];
	t_0 = st[5];
	tmp = st[6];				// q[k]*s[k-1]

	BnSetInt(s_2, 1);
	BnSetInt(s_1, 0);
	BnSetInt(t_2, 0);
	BnSetInt(t_1, 1);

	m1 = m;
	n1 = n;
	for (;;)
	{
		////////////////////////////
		// r1 = m / n
		result = BnDiv(q, r1, m1, n1);
		if (result != BN_ERR_SUCCESS) goto _EXIT;

		m1 = n1;
		n1 = r1;
		if (BnCmpUInt(r1, 0) == 0)
			break;

		// s[k] = s[k-2] - q[k]*s[k-1]
		BnMul(tmp, q, s_1);
		BnSub(s_0, s_2, tmp);
		// t[k] = t[k-2] - q[k]*t[k-1]
		BnMul(tmp, q, t_1);
		BnSub(t_0, t_2, tmp);
		//
		swap = s_2;
		s_2 = s_1;
		s_1 = s_0;
		s_0 = swap;
		swap = t_2;
		t_2 = t_1;
		t_1 = t_0;
		t_0 = swap;

		////////////////////////////
		// r2 = m / n
		result = BnDiv(q, r2, m1, n1);
		if (result != BN_ERR_SUCCESS) goto _EXIT;

		m1 = n1;
		n1 = r2;
		if (BnCmpUInt(r2, 0) == 0)
			break;

		// s[k] = s[k-2] - q[k]*s[k-1]
		BnMul(tmp, q, s_1);
		BnSub(s_0, s_2, tmp);
		// t[k] = t[k-2] - q[k]*t[k-1]
		BnMul(tmp, q, t_1);
		BnSub(t_0, t_2, tmp);
		//
		swap = s_2;
		s_2 = s_1;
		s_1 = s_0;
		s_0 = swap;
		swap = t_2;
		t_2 = t_1;
		t_1 = t_0;
		t_0 = swap;
	}
	if (r != NULL) {
		BnSet(r, m1);
	}
	if (a != NULL) {
		// if ( r == 1 ) --> a is inverse of m (m*a mod n = 1)
		if (isUnsigned && BN_ISNEG(s_1)) {
			BnAdd(a, s_1, n);
		}
		else {
			BnSet(a, s_1);		// if ( r == 1 ) --> a is inverse of m (m*a mod n = 1)
		}
	}
	if (b != NULL) {
		if (isUnsigned && BN_ISNEG(t_1)) {
			BnAdd(b, t_1, m);
		}
		else {
			BnSet(b, t_1);
		}
	}

	result = BN_ERR_SUCCESS;
_EXIT:
	BN_SAFEFREE(r1);
	BN_SAFEFREE(r2);
	BN_SAFEFREE(q);

	for (i = 0; i < 7; i++)
	{
		BN_SAFEFREE(st[i]);
	}
	return result;
}
