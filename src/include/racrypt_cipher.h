/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_CIPHER_H__
#define __RA_CIPHER_H__

#include "racrypt_com.h"

#ifdef __cplusplus
extern "C" {
#endif

struct RaBlockCipher;

typedef void (*blockCipherEncryptBlock)(struct RaBlockCipher *ctx, const uint8_t *input, uint8_t *output);
typedef void (*blockCipherDecryptBlock)(struct RaBlockCipher *ctx, const uint8_t *input, uint8_t *output);

enum RaBlockCipherMode {
	RA_BLOCK_MODE_ECB,
	RA_BLOCK_MODE_CBC,
	RA_BLOCK_MODE_CFB,
	RA_BLOCK_MODE_OFB,
	RA_BLOCK_MODE_CTR
};

enum RaBlockCipherPaddingType {
	RA_BLOCK_PADDING_NONE,
	RA_BLOCK_PADDING_ZERO,
	RA_BLOCK_PADDING_PKCS7
};
struct RaBlockCipher {
	blockCipherEncryptBlock encryptBlock;
	blockCipherDecryptBlock decryptBlock;
	enum RaBlockCipherMode opMode;
	uint32_t *iv;			// block size / 4
	uint8_t *buffer;		// block size
	int blockSize;
	int bufferFilled;
};



#define RA_KEY_LEN_DES			8
#define RA_KEY_LEN_3DES_112		16
#define RA_KEY_LEN_3DES_168		24

#define RA_KEY_LEN_SEED			16

#define RA_KEY_LEN_AES_128		16
#define RA_KEY_LEN_AES_192		24
#define RA_KEY_LEN_AES_256		32

#define RA_KEY_LEN_ARIA_128		16
#define RA_KEY_LEN_ARIA_192		24
#define RA_KEY_LEN_ARIA_256		32

#define RA_BLOCK_LEN_DES		8
#define RA_BLOCK_LEN_AES		16
#define RA_BLOCK_LEN_SEED		16
#define RA_BLOCK_LEN_ARIA		16
#define RA_BLOCK_LEN_BLOWFISH	8

#define RA_BLOCK_LEN_MAX		16



/*****************************************************
 Symmetric key cipher algorithm: AES
 *****************************************************/

enum RaAesKeyType {
	RA_AES_128,
	RA_AES_192,
	RA_AES_256,
};

struct RaAesCtx {
	int nr;
	uint32_t key[15][4];
	uint32_t rev_key[15][4];
	uint32_t iv[RA_BLOCK_LEN_AES / 4];
	uint8_t buffer[RA_BLOCK_LEN_AES];

	struct RaBlockCipher blockCipher;
};

/**
* @brief Create AES block encryption/decryption context
*
* @param key		symmetric key
* @param keyType	type of key. RA_AES_128 or RA_AES_192 or RA_AES_256
* @param opMode		block cipher modes of operation
* @param ctxp		pointer for receiving AES context
* @note The key length must be 128bit when the key type is RA_AES_128, and 192bit for RA_AES_192, 256bit for RA_AES_256
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaAesCreate(const uint8_t *key, enum RaAesKeyType keyType, enum RaBlockCipherMode opMode, struct RaAesCtx **ctxp);

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
void RaAesInit(struct RaAesCtx *ctx, const uint8_t *key, enum RaAesKeyType keyType, enum RaBlockCipherMode opMode);

/**
* @brief Set initialization vector
*
* @param ctx		AES context
* @param iv			initialization vector
*/
void RaAesSetIV(struct RaAesCtx *ctx, const uint8_t iv[16]);

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
int RaAesEncryptFinal(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);

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
int RaAesDecryptFinal(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);



/*****************************************************
 Symmetric key cipher algorithm: DES
 *****************************************************/

enum RaDesKeyType {
	RA_DES,
	RA_DES_EDE2,
	RA_DES_EDE3,
	RA_3DES = RA_DES_EDE3
};

struct RaDesCtx {
	enum RaDesKeyType keyType;
	uint32_t round_key1[2][16];
	uint32_t round_key2[2][16];
	uint32_t round_key3[2][16];

	uint32_t iv[RA_BLOCK_LEN_DES / 4];
	uint8_t buffer[RA_BLOCK_LEN_DES];

	struct RaBlockCipher blockCipher;
};

/**
* @brief Create DES block encryption/decryption context
*
* @param key		symmetric key
* @param keyType	type of key. RA_DES or RA_DES_EDE2 or RA_DES_EDE3
* @param opMode		block cipher modes of operation
* @param ctxp		pointer for receiving DES context
* @note The key length must be 8byte(56bit) when the key type is RA_DES, and 16byte for RA_DES_EDE2, 32byte for RA_DES_EDE3
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaDesCreate(const uint8_t *key, enum RaDesKeyType keyType, enum RaBlockCipherMode opMode, struct RaDesCtx **ctxp);

/**
* @brief Destroy DES block encryption/decryption context
*
* @param ctx		DES context to destroy
*/
void RaDesDestroy(struct RaDesCtx *ctx);

/**
* @brief Initialize DES block encryption/decryption context
*
* @param ctx		DES context
* @param key		symmetric key
* @param keyType	type of key. RA_DES or RA_DES_EDE2 or RA_DES_EDE3
* @param opMode		block cipher modes of operation
* @note The key length must be 8byte(56bit) when the key type is RA_DES, and 16byte for RA_DES_EDE2, 32byte for RA_DES_EDE3
*/
void RaDesInit(struct RaDesCtx *ctx, const uint8_t *key, enum RaDesKeyType keyType, enum RaBlockCipherMode opMode);

/**
* @brief Set initialization vector
*
* @param ctx		DES context
* @param iv			initialization vector
*/
void RaDesSetIV(struct RaDesCtx *ctx, const uint8_t iv[8]);

/**
* @brief Get initialization vector
*
* @param ctx		DES context
* @param iv			space to get initialization vector
*/
void RaDesGetIV(struct RaDesCtx *ctx, /*out*/uint8_t iv[8]);

/**
* @brief DES Encrypt given byte array
*
* DES algorithm block size is 64bit. If input data is not aligned to 64bits, ouput length can be different from the input length.\n
* And the rest of the data that is not encrypted in this time is combined with the following input data for encryption.\n
* If the input data length is various, prepair additional 8bytes of output data space than input data.\n
* example)\n
* - 1st: input: 30byte, output 24byte. 6bytes are remained in the internal buffer
* - 2nd: input: 18byte, output 24byte. The Previous data is combined and encrypted together
* @param ctx		DES context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @return			written length in bytes
*/
int RaDesEncrypt(struct RaDesCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief DES Encrypt given byte array with padding
*
* The output data is aligned and expanded to 8 bytes.\n
* PKCS7 padding can be up to 8 bytes long.
* @param ctx		DES context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaDesEncryptFinal(struct RaDesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);

/**
* @brief DES Decrypt given byte array
*
* DES algorithm block size is 64bit. If input data is not aligned to 64bits, ouput length can be different from the input length.\n
* And the rest of the data that is not decrypted in this time is combined with the following input data for decryption.\n
* If the input data length is various, prepair additional 8bytes of output data space than input data.\n
* @param ctx		DES context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @return			written length in bytes
*/
int RaDesDecrypt(struct RaDesCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief DES Decrypt given byte array with padding
*
* If the input data is padded with PKCS7 padding, the return value, which is output length, is the length excluding padding
* @param ctx		DES context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaDesDecryptFinal(struct RaDesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);



/*****************************************************
 Symmetric key cipher algorithm: SEED
 *****************************************************/

struct RaSeedCtx {
	uint32_t round_key0[16];
	uint32_t round_key1[16];

	uint32_t iv[RA_BLOCK_LEN_SEED / 4];
	uint8_t buffer[RA_BLOCK_LEN_SEED];

	struct RaBlockCipher blockCipher;
};

/**
* @brief Create SEED block encryption/decryption context
*
* @param key		symmetric key
* @param opMode		block cipher modes of operation
* @param ctxp		pointer for receiving SEED context
* @note The key length must be 16byte(128bit)
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaSeedCreate(const uint8_t *key, enum RaBlockCipherMode opMode, struct RaSeedCtx **ctxp);

/**
* @brief Destroy SEED block encryption/decryption context
*
* @param ctx		SEED context to destroy
*/
void RaSeedDestroy(struct RaSeedCtx *ctx);

/**
* @brief Initialize SEED block encryption/decryption context
*
* @param ctx		SEED context
* @param key		symmetric key
* @param opMode		block cipher modes of operation
* @note The key length must be 16byte(128bit)
*/
void RaSeedInit(struct RaSeedCtx *ctx, const uint8_t *key, enum RaBlockCipherMode opMode);

/**
* @brief Set initialization vector
*
* @param ctx		SEED context
* @param iv			initialization vector
*/
void RaSeedSetIV(struct RaSeedCtx *ctx, const uint8_t iv[16]);

/**
* @brief Get initialization vector
*
* @param ctx		SEED context
* @param iv			space to get initialization vector
*/
void RaSeedGetIV(struct RaSeedCtx *ctx, /*out*/uint8_t iv[16]);

/**
* @brief SEED Encrypt given byte array
*
* SEED algorithm block size is 128bit. If input data is not aligned to 128bits, ouput length can be different from the input length.\n
* And the rest of the data that is not encrypted in this time is combined with the following input data for encryption.\n
* If the input data length is various, prepair additional 16bytes of output data space than input data.\n
* example)\n
* - 1st: input: 30byte, output 16byte. 14bytes are remained in the internal buffer
* - 2nd: input: 18byte, output 32byte. The Previous data is combined and encrypted together
* @param ctx		SEED context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @return			written length in bytes
*/
int RaSeedEncrypt(struct RaSeedCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief SEED Encrypt given byte array with padding
*
* The output data is aligned and expanded to 16 bytes.\n
* PKCS7 padding can be up to 16 bytes long.
* @param ctx		SEED context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaSeedEncryptFinal(struct RaSeedCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);

/**
* @brief SEED Decrypt given byte array
*
* SEED algorithm block size is 128bit. If input data is not aligned to 128bits, ouput length can be different from the input length.\n
* And the rest of the data that is not decrypted in this time is combined with the following input data for decryption.\n
* If the input data length is various, prepair additional 16bytes of output data space than input data.\n
* @param ctx		SEED context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @return			written length in bytes
*/
int RaSeedDecrypt(struct RaSeedCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief SEED Decrypt given byte array with padding
*
* If the input data is padded with PKCS7 padding, the return value, which is output length, is the length excluding padding
* @param ctx		SEED context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaSeedDecryptFinal(struct RaSeedCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);


/*****************************************************
 Symmetric key cipher algorithm: ARIA
 *****************************************************/

enum RaAriaKeyType {
	RA_ARIA_128,
	RA_ARIA_192,
	RA_ARIA_256,
};

struct RaAriaCtx {
	int nr;
	uint32_t round_key[17][4];
	uint32_t rev_key[17][4];

	uint32_t iv[RA_BLOCK_LEN_ARIA / 4];
	uint8_t buffer[RA_BLOCK_LEN_ARIA];

	struct RaBlockCipher blockCipher;
};

/**
* @brief Create ARIA block encryption/decryption context
*
* @param key		symmetric key
* @param opMode		block cipher modes of operation
* @param ctxp		pointer for receiving ARIA context
* @note The key length must be 128bit when the key type is RA_ARIA_128, and 192bit for RA_ARIA_192, 256bit for RA_ARIA_256
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaAriaCreate(const uint8_t *key, enum RaAriaKeyType keyType, enum RaBlockCipherMode opMode, struct RaAriaCtx **ctxp);

/**
* @brief Destroy ARIA block encryption/decryption context
*
* @param ctx		ARIA context to destroy
*/
void RaAriaDestroy(struct RaAriaCtx *ctx);

/**
* @brief Initialize ARIA block encryption/decryption context
*
* @param ctx		ARIA context
* @param key		symmetric key
* @param opMode		block cipher modes of operation
* @note The key length must be 128bit when the key type is RA_ARIA_128, and 192bit for RA_ARIA_192, 256bit for RA_ARIA_256
*/
void RaAriaInit(struct RaAriaCtx *ctx, const uint8_t *key, enum RaAriaKeyType keyType, enum RaBlockCipherMode opMode);

/**
* @brief Set initialization vector
*
* @param ctx		ARIA context
* @param iv			initialization vector
*/
void RaAriaSetIV(struct RaAriaCtx *ctx, const uint8_t iv[16]);

/**
* @brief Get initialization vector
*
* @param ctx		ARIA context
* @param iv			space to get initialization vector
*/
void RaAriaGetIV(struct RaAriaCtx *ctx, /*out*/uint8_t iv[16]);

/**
* @brief ARIA Encrypt given byte array
*
* ARIA algorithm block size is 128bit. If input data is not aligned to 128bits, ouput length can be different from the input length.\n
* And the rest of the data that is not encrypted in this time is combined with the following input data for encryption.\n
* If the input data length is various, prepair additional 16bytes of output data space than input data.\n
* example)\n
* - 1st: input: 30byte, output 16byte. 14bytes are remained in the internal buffer
* - 2nd: input: 18byte, output 32byte. The Previous data is combined and encrypted together
* @param ctx		ARIA context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @return			written length in bytes
*/
int RaAriaEncrypt(struct RaAriaCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief ARIA Encrypt given byte array with padding
*
* The output data is aligned and expanded to 16 bytes.\n
* PKCS7 padding can be up to 16 bytes long.
* @param ctx		ARIA context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaAriaEncryptFinal(struct RaAriaCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);

/**
* @brief ARIA Decrypt given byte array
*
* ARIA algorithm block size is 128bit. If input data is not aligned to 128bits, ouput length can be different from the input length.\n
* And the rest of the data that is not decrypted in this time is combined with the following input data for decryption.\n
* If the input data length is various, prepair additional 16bytes of output data space than input data.\n
* @param ctx		ARIA context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @return			written length in bytes
*/
int RaAriaDecrypt(struct RaAriaCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief ARIA Decrypt given byte array with padding
*
* If the input data is padded with PKCS7 padding, the return value, which is output length, is the length excluding padding
* @param ctx		ARIA context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaAriaDecryptFinal(struct RaAriaCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);


/*****************************************************
 Symmetric key cipher algorithm: Blowfish
 *****************************************************/

struct RaBlowfishCtx {
	uint32_t p_array[18];
	uint32_t sbox[4][256];

	uint32_t iv[RA_BLOCK_LEN_BLOWFISH / 4];
	uint8_t buffer[RA_BLOCK_LEN_BLOWFISH];

	struct RaBlockCipher blockCipher;
};

/**
* @brief Create Blowfish block encryption/decryption context
*
* @param key		symmetric key
* @param keyLen		symmetric key length
* @param opMode		block cipher modes of operation
* @param ctxp		pointer for receiving Blowfish context
* @note The key length can be from 1 to 72. Key data beyond 72 bytes is not used.
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaBlowfishCreate(const uint8_t *key, int keyLen, enum RaBlockCipherMode opMode, struct RaBlowfishCtx **ctxp);

/**
* @brief Destroy Blowfish block encryption/decryption context
*
* @param ctx		Blowfish context to destroy
*/
void RaBlowfishDestroy(struct RaBlowfishCtx* ctx);

/**
* @brief Initialize Blowfish block encryption/decryption context
*
* @param ctx		Blowfish context
* @param key		symmetric key
* @param keyLen		symmetric key length
* @param opMode		block cipher modes of operation
* @note The key length can be from 1 to 72. Key data beyond 72 bytes is not used.
*/
void RaBlowfishInit(struct RaBlowfishCtx *ctx, const uint8_t *key, int keyLen, enum RaBlockCipherMode opMode);

/**
* @brief Set initialization vector
*
* @param ctx		Blowfish context
* @param iv			initialization vector
*/
void RaBlowfishSetIV(struct RaBlowfishCtx *ctx, const uint8_t iv[8]);

/**
* @brief Get initialization vector
*
* @param ctx		Blowfish context
* @param iv			space to get initialization vector
*/
void RaBlowfishGetIV(struct RaBlowfishCtx *ctx, /*out*/uint8_t iv[8]);

/**
* @brief Blowfish Encrypt given byte array
*
* Blowfish algorithm block size is 64bit. If input data is not aligned to 64bits, ouput length can be different from the input length.\n
* And the rest of the data that is not encrypted in this time is combined with the following input data for encryption.\n
* If the input data length is various, prepair additional 8bytes of output data space than input data.\n
* example)\n
* - 1st: input: 30byte, output 24byte. 6bytes are remained in the internal buffer
* - 2nd: input: 18byte, output 24byte. The Previous data is combined and encrypted together
* @param ctx		Blowfish context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @return			written length in bytes
*/
int RaBlowfishEncrypt(struct RaBlowfishCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief Blowfish Encrypt given byte array with padding
*
* The output data is aligned and expanded to 8 bytes.\n
* PKCS7 padding can be up to 8 bytes long.
* @param ctx		Blowfish context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaBlowfishEncryptFinal(struct RaBlowfishCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);

/**
* @brief Blowfish Decrypt given byte array
*
* Blowfish algorithm block size is 64bit. If input data is not aligned to 64bits, ouput length can be different from the input length.\n
* And the rest of the data that is not decrypted in this time is combined with the following input data for decryption.\n
* If the input data length is various, prepair additional 8bytes of output data space than input data.\n
* @param ctx		Blowfish context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @return			written length in bytesd
*/
int RaBlowfishDecrypt(struct RaBlowfishCtx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief Blowfish Decrypt given byte array with padding
*
* If the input data is padded with PKCS7 padding, the return value, which is output length, is the length excluding padding
* @param ctx		Blowfish context
* @param input		data to be decrypted
* @param length		the length of input data
* @param output		space in which the decrypted data will be written
* @param paddingType	padding type
* @return			written length in bytes
*/
int RaBlowfishDecryptFinal(struct RaBlowfishCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType);

/*****************************************************
 Symmetric key cipher algorithm: RC4
 *****************************************************/

struct RaRc4Ctx {
	uint8_t S[256];
	int x;
	int y;
};

/**
* @brief Create RC4 stream encryption/decryption context
*
* @param key		symmetric key
* @param keyLen		length of key
* @param ctxp		pointer for receiving RC4 context
* @retval RA_ERR_SUCCESS		success
* @retval RA_ERR_OUT_OF_MEMORY	memory allocation failure
*/
int RaRc4Create(const uint8_t *key, int keyLen, struct RaRc4Ctx **ctxp);

/**
* @brief Destroy RC4 stream encryption/decryption context
*
* @param ctx		RC4 context to destroy
*/
void RaRc4Destroy(struct RaRc4Ctx *ctx);

/**
* @brief Initialize RC4 stream encryption/decryption context
*
* @param key		symmetric key
* @param keyLen		length of key
* @param ctxp		pointer for receiving RC4 context
*/
void RaRc4Init(struct RaRc4Ctx *ctx, const uint8_t *key, int keyLen);

/**
* @brief RC4 Encrypt given byte array
*
* @param ctx		RC4 context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @note Actually RC4 algorithm's encryption and decryption are same
* @return			written length in bytes
*/
int RaRc4Encrypt(struct RaRc4Ctx *ctx, const uint8_t *input, int length, uint8_t *output);

/**
* @brief RC4 Decrypt given byte array
*
* @param ctx		RC4 context
* @param input		data to be encrypted
* @param length		the length of input data
* @param output		space in which the encrypted data will be written
* @note Actually RC4 algorithm's encryption and decryption are same
* @return			written length in bytes
*/
int RaRc4Decrypt(struct RaRc4Ctx *ctx, const uint8_t *input, int length, uint8_t *output);

#ifdef __cplusplus
}
#endif


#endif
