/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __BN_BNPRINT_H__
#define __BN_BNPRINT_H__

#ifdef __cplusplus
extern "C" {
#endif

void BnPrint(struct RaBigNumber* bn);
void BnPrintLn(struct RaBigNumber* bn);
int BnSPrint(struct RaBigNumber* bn, char* buffer, int bufferlen);
void BnPrint10(struct RaBigNumber* bn);
void BnPrint10Ln(struct RaBigNumber* bn);
int BnSPrint10(struct RaBigNumber* bn, char* buffer, int bufferlen);

#ifdef __cplusplus
}
#endif

#endif
