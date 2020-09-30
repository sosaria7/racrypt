/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_BLOCK_CIPHER_H__
#define __RA_BLOCK_CIPHER_H__

#include "../include/racrypt_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHILD_OF(h, child_type, parent)		(child_type*)((uint8_t*)h - (intptr_t)&((child_type*)0)->parent)

void RaBlockCipherInit(struct RaBlockCipher *ctx, blockCipherEncryptBlock encryptBlock, blockCipherEncryptBlock decryptBlock, enum RaBlockCipherMode opMode, int blockSize, uint32_t *iv, uint8_t *buffer);
int RaBlockCipherEncrypt(struct RaBlockCipher *ctx, const uint8_t *input, int length, uint8_t *output);
int RaBlockCipherEncryptFinal(struct RaBlockCipher *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);
int RaBlockCipherDecrypt(struct RaBlockCipher *ctx, const uint8_t *input, int length, uint8_t *output);
int RaBlockCipherDecryptFinal(struct RaBlockCipher *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);
void RaBlockCipherSetIV(struct RaBlockCipher *ctx, const uint8_t *iv);
void RaBlockCipherGetIV(struct RaBlockCipher *ctx, /*out*/uint8_t *iv);

#ifdef __cplusplus
}
#endif

#endif
