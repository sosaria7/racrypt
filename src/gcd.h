/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#pragma once
#ifndef __RA_GCD_H__
#define __RA_GCD_H__

#include "bignumber.h"

#ifdef __cplusplus
extern "C" {
#endif

int GetGCD(/*out*/struct BigNumber *r, struct BigNumber *m, struct BigNumber *n);
int GetGCDEx(/*out,nullable*/struct BigNumber *r, /*out*/struct BigNumber *a, /*out*/struct BigNumber *b, struct BigNumber *m, struct BigNumber *n, int isUnsigned);

#ifdef __cplusplus
}
#endif


#endif
