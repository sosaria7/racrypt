/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#pragma once
#ifndef __RA_RSA_H__
#define __RA_RSA_H__

#include "bignumber.h"

#ifdef __cplusplus
extern "C" {
#endif

struct RSAKeyPair;

int RSACreateKeyPair(int bit, /*out*/struct RSAKeyPair** keyPair);
void RSADestroyKeyPair(struct RSAKeyPair* key);
int RSAEncrypt(struct RSAKeyPair* key, struct BigNumber *message, /*out*/struct BigNumber *encrypted);
int RSADecrypt(struct RSAKeyPair* key, struct BigNumber *encrypted, /*out*/struct BigNumber *message);
int RSAVerify(struct RSAKeyPair* key, struct BigNumber *encrypted, struct BigNumber *message);

int RSACreateKeyPub(uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp);
int RSACreateKeyPriv(uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp);
int RSACreateKeyFromByteArray(uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp);
int RSAPrivKeyToByteArray(struct RSAKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen);
int RSAPubKeyToByteArray(struct RSAKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen);

#ifdef __cplusplus
}
#endif


#endif
