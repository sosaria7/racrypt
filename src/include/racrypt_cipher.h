/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_CIPHER_H__
#define __RA_CIPHER_H__

#include "racrypt_com.h"

#ifdef __cplusplus
extern "C" {
#endif

enum RaAesKeyType {
	RA_AES_128,
	RA_AES_192,
	RA_AES_256,
};
#define RA_KEY_LEN_AES_128		16
#define RA_KEY_LEN_AES_192		24
#define RA_KEY_LEN_AES_256		32
#define RA_BLOCK_LEN_AES		16

enum RaAesMode {
	RA_AES_MODE_ECB,
	RA_AES_MODE_CBC,
	RA_AES_MODE_CFB,
	RA_AES_MODE_OFB
};

enum RaAesPaddingType {
	RA_AES_PADDING_NONE,
	RA_AES_PADDING_ZERO,
	RA_AES_PADDING_PKCS7
};
struct RaAesCtx {
	enum RaAesMode opMode;
	int nr;
	uint32_t key[15][4];
	uint32_t rev_key[15][4];
	uint32_t iv[4];
	uint8_t buffer[16];
	int bufferFilled;
};

/**
* @brief Create AES block encryption/decryption context
*
* @param key		symmetric key
* @param keyType	type of key. RA_AES_128 or RA_AES_192 or RA_AES_256
* @param opMode		block cipher modes of operation
* @param ctxp		pointer for receiving AES context
* @note The key length must be 128bit when the key type is RA_AES_128, and 192bit for RA_AES_192, 256bit for RA_AES_256
* @retval BN_ERR_SUCCESS		success
* @retval BN_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaAesCreate(const uint8_t *key, enum RaAesKeyType keyType, enum RaAesMode opMode, struct RaAesCtx **ctxp);

/**
* @brief Destroy AES block encryption/decryption context
*
* @param ctx		AES context to destroy
*/
void RaAesDestroy(struct RaAesCtx *ctx);

/**
* @brief Initialize AES block encryption/decryption context
*
* @param ctx		AES context
* @param key		symmetric key
* @param keyType	type of key. RA_AES_128 or RA_AES_192 or RA_AES_256
* @param opMode		block cipher modes of operation
* @note The key length must be 128bit when the key type is RA_AES_128, and 192bit for RA_AES_192, 256bit for RA_AES_256
*/
void RaAesInit(struct RaAesCtx *ctx, const uint8_t *key, enum RaAesKeyType keyType, enum RaAesMode opMode);

/**
* @brief Set initialization vector
*
* @param ctx		AES context
* @param iv			initialization vector
*/
void RaAesSetIV(struct RaAesCtx *ctx, uint8_t iv[16]);

/**
* @brief Get initialization vector
*
* @param ctx		AES context
* @param iv			space to get initialization vector
*/
void RaAesGetIV(struct RaAesCtx *ctx, /*out*/uint8_t iv[16]);

/**
* @brief AES Encrypt given byte array
*
* AES algorithm block size is 128bit. If input data is not aligned to 128bits, ouput length can be different from the input length.\n
* And the rest of the data that is not encrypted in this time is combined with the following input data for encryption.\n
* If the input data length is various, prepair additional 16bytes of output data space than input data.\n
* example)\n
* - 1st: input: 30byte, output 16byte. 14bytes are remained in the internal buffer
* - 2nd: input: 18byte, output 32byte. The Previous data is combined and encrypted together
* @param ctx		AES context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @return			written length in bytes
*/
int RaAesEncrypt(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief AES Encrypt given byte array with padding
*
* The output data is aligned and expanded to 16 bytes.\n
* PKCS7 padding can be up to 16 bytes long.
* @param ctx		AES context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaAesEncryptFinal(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaAesPaddingType paddingType);

/**
* @brief AES Decrypt given byte array
*
* AES algorithm block size is 128bit. If input data is not aligned to 128bits, ouput length can be different from the input length.\n
* And the rest of the data that is not decrypted in this time is combined with the following input data for decryption.\n
* If the input data length is various, prepair additional 16bytes of output data space than input data.\n
* @param ctx		AES context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @return			written length in bytes
*/
int RaAesDecrypt(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief AES Decrypt given byte array with padding
*
* If the input data is padded with PKCS7 padding, the return value, which is output length, is the length excluding padding
* @param ctx		AES context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaAesDecryptFinal(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaAesPaddingType paddingType);

#ifdef __cplusplus
}
#endif


#endif
