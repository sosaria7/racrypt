/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#pragma once
#ifndef __RA_PRIME_H__
#define __RA_PRIME_H__

#include "bignumber.h"

int GenPrimeNumber(struct BigNumber *bn, int bit);
int GenPrimeNumberEx(struct BigNumber *bn, int bit, int(*progress)(int count, void* userData), void* userData, uint32_t *seedp);
int IsPrimeNumber(struct BigNumber *bn);

#endif
