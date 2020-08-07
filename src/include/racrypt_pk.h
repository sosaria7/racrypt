/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#pragma once
#ifndef __RA_PK_H__
#define __RA_PK_H__

#include "racrypt_com.h"

#ifdef __cplusplus
extern "C" {
#endif

struct RSAKeyPair;

int RSACreateKeyPair(int bit, /*out*/struct RSAKeyPair** keyPair);
void RSADestroyKeyPair(struct RSAKeyPair* key);
int RSAEncrypt(struct RSAKeyPair* key, struct BigNumber *message, /*out*/struct BigNumber *encrypted);
int RSADecrypt(struct RSAKeyPair* key, struct BigNumber *encrypted, /*out*/struct BigNumber *message);
int RSASign( struct RSAKeyPair* key, struct BigNumber *message, /*out*/struct BigNumber *secure );
int RSAVerify(struct RSAKeyPair* key, struct BigNumber *encrypted, struct BigNumber *message);
int RSAKeyBitLength(struct RSAKeyPair* key);
int RSAVerifyKey(struct RSAKeyPair *key);

int RSACreateKeyPub(const uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp);
int RSACreateKeyPriv(const uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp);
int RSACreateKeyFromByteArray(const uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp);
int RSAPrivKeyToByteArray(struct RSAKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen);
int RSAPubKeyToByteArray(struct RSAKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen);

#ifdef __cplusplus
}
#endif


#endif
