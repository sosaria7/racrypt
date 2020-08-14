/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_PK_H__
#define __RA_PK_H__

#include "racrypt_com.h"

#ifdef __cplusplus
extern "C" {
#endif

struct RaRsaKeyPair;

int RaRsaCreateKeyPair(int bit, /*out*/struct RaRsaKeyPair** keyPair);
void RaRsaDestroyKeyPair(struct RaRsaKeyPair* key);
int RaRsaEncrypt(struct RaRsaKeyPair* key, struct BigNumber *message, /*out*/struct BigNumber *encrypted);
int RaRsaDecrypt(struct RaRsaKeyPair* key, struct BigNumber *encrypted, /*out*/struct BigNumber *message);
int RaRsaSign( struct RaRsaKeyPair* key, struct BigNumber *message, /*out*/struct BigNumber *secure );
int RaRsaVerify(struct RaRsaKeyPair* key, struct BigNumber *encrypted, struct BigNumber *message);
int RaRsaKeyBitLength(struct RaRsaKeyPair* key);
int RaRsaVerifyKey(struct RaRsaKeyPair *key);

int RaRsaCreateKeyPub(const uint8_t *asn1Data, int dataLen, /*out*/struct RaRsaKeyPair** keyp);
int RaRsaCreateKeyPriv(const uint8_t *asn1Data, int dataLen, /*out*/struct RaRsaKeyPair** keyp);
int RaRsaCreateKeyFromByteArray(const uint8_t *asn1Data, int dataLen, /*out*/struct RaRsaKeyPair** keyp);
int RaRsaPrivKeyToByteArray(struct RaRsaKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen);
int RaRsaPubKeyToByteArray(struct RaRsaKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen);

#ifdef __cplusplus
}
#endif


#endif
