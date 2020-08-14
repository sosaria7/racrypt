/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __BN_BNPRINT_H__
#define __BN_BNPRINT_H__

void BnPrint(struct BigNumber* bn);
void BnPrintLn(struct BigNumber* bn);
int BnSPrint(struct BigNumber* bn, char* buffer, int bufferlen);
void BnPrint10(struct BigNumber* bn);
void BnPrint10Ln(struct BigNumber* bn);
int BnSPrint10(struct BigNumber* bn, char* buffer, int bufferlen);


#endif
