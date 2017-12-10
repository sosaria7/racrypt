/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#pragma once
#ifndef __RA_MONT_EXP_MOD__
#define __RA_MONT_EXP_MOD__

#include "bignumber.h"

#ifdef __cplusplus
extern "C" {
#endif

struct MontCtx;

int MontCreate(struct BigNumber *N, /*out*/struct MontCtx **montCtx);
void MontDestroy(struct MontCtx *ctx);
int MontExpMod(struct MontCtx *ctx, /*out*/struct BigNumber *r, struct BigNumber *a, struct BigNumber *b);

#ifdef __cplusplus
}
#endif


#endif
