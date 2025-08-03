/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RA_PK_H__
#define __RA_PK_H__

#include "racrypt_com.h"
#include "racrypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

struct RaRsaKeyPair;

/**
* @brief Create RSA key pair
*
* @param bit		key size in bits (typically 1024, 2048, 3072, 4096)
* @param keyPair	pointer for receiving RSA key pair
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_OUT_OF_MEMORY	    memory allocation failure
*/
int RaRsaCreateKeyPair(int bit, /*out*/struct RaRsaKeyPair** keyPair);

/**
* @brief Destroy RSA key pair
*
* @param key		RSA key pair to destroy
*/
void RaRsaDestroyKeyPair(struct RaRsaKeyPair* key);

/**
* @brief Encrypt message using RSA public key
*
* @param key		RSA key pair containing public key
* @param message	plaintext message as big number
* @param encrypted	output buffer for encrypted message
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_NUMBER_SIZE	    message size is larger than modulus
* @note Message must be smaller than modulus
*/
int RaRsaEncrypt(struct RaRsaKeyPair* key, struct RaBigNumber *message, /*out*/struct RaBigNumber *encrypted);

/**
* @brief Decrypt message using RSA private key
*
* @param key		RSA key pair containing private key
* @param encrypted	encrypted message as big number
* @param message	output buffer for decrypted message
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_INVALID_DATA	    the key does not contain private key
*/
int RaRsaDecrypt(struct RaRsaKeyPair* key, struct RaBigNumber *encrypted, /*out*/struct RaBigNumber *message);

/**
* @brief Sign message using RSA private key
*
* @param key		RSA key pair containing private key
* @param message	message hash to sign
* @param secure		output buffer for signature
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_INVALID_DATA   	the key does not contain private key
*/
int RaRsaSign( struct RaRsaKeyPair* key, struct RaBigNumber *message, /*out*/struct RaBigNumber *secure );

/**
* @brief Verify signature using RSA public key
*
* @param key		RSA key pair containing public key
* @param encrypted	signature to verify
* @param message	original message hash
* @retval RA_ERR_SUCCESS		    signature valid
* @retval RA_ERR_INVALID_DATA   	signature invalid
*/
int RaRsaVerify(struct RaRsaKeyPair* key, struct RaBigNumber *encrypted, struct RaBigNumber *message);

/**
* @brief Get RSA key bit length
*
* @param key		RSA key pair
* @return			key size in bits, or negative value on error
*/
int RaRsaKeyBitLength(struct RaRsaKeyPair* key);

/**
* @brief Verify RSA key pair validity
*
* @param key		RSA key pair to verify
* @retval RA_ERR_SUCCESS		    key pair is valid
* @retval RA_ERR_INVALID_DATA	    key pair is invalid
* @retval RA_ERR_OUT_OF_MEMORY	    memory allocation failure
*/
int RaRsaVerifyKey(struct RaRsaKeyPair *key);

/**
* @brief Create RSA public key from ASN.1 encoded data
*
* @param asn1Data	ASN.1 DER encoded public key data
* @param dataLen	length of ASN.1 data
* @param keyp		pointer for receiving RSA key pair
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_INVALID_DATA   	invalid ASN.1 data
* @retval RA_ERR_OUT_OF_MEMORY	    memory allocation failure
*/
int RaRsaCreateKeyPub(const uint8_t *asn1Data, int dataLen, /*out*/struct RaRsaKeyPair** keyp);

/**
* @brief Create RSA private key from ASN.1 encoded data
*
* @param asn1Data	ASN.1 DER encoded private key data
* @param dataLen	length of ASN.1 data
* @param keyp		pointer for receiving RSA key pair
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_INVALID_DATA   	invalid ASN.1 data
* @retval RA_ERR_OUT_OF_MEMORY	    memory allocation failure
*/
int RaRsaCreateKeyPriv(const uint8_t *asn1Data, int dataLen, /*out*/struct RaRsaKeyPair** keyp);

/**
* @brief Create RSA key from ASN.1 encoded data (auto-detect public/private)
*
* @param asn1Data	ASN.1 DER encoded key data
* @param dataLen	length of ASN.1 data
* @param keyp		pointer for receiving RSA key pair
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_INVALID_DATA   	invalid ASN.1 data
* @retval RA_ERR_OUT_OF_MEMORY	    memory allocation failure
*/
int RaRsaCreateKeyFromByteArray(const uint8_t *asn1Data, int dataLen, /*out*/struct RaRsaKeyPair** keyp);

/**
* @brief Export RSA private key to ASN.1 encoded data
*
* @param key		RSA key pair containing private key
* @param asn1Data	output buffer for ASN.1 DER encoded data
* @param dataLen	size of output buffer
* @param resultLen	actual length of encoded data
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_INVALID_DATA       the key does not contain private key
* @retval RA_ERR_OUT_OF_BUFFER  	buffer too small
* @retval RA_ERR_OUT_OF_MEMORY	    memory allocation failure
* @note The output format is PKCS#1 v1.5 private key format
*/
int RaRsaPrivKeyToByteArray(struct RaRsaKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen);

/**
* @brief Export RSA public key to ASN.1 encoded data
*
* @param key		RSA key pair containing public key
* @param asn1Data	output buffer for ASN.1 DER encoded data
* @param dataLen		size of output buffer
* @param resultLen	actual length of encoded data
* @retval RA_ERR_SUCCESS		    success
* @retval RA_ERR_OUT_OF_BUFFER  	buffer too small
* @retval RA_ERR_OUT_OF_MEMORY	    memory allocation failure
* @note The output format is PKCS#1 v1.5 public key format
*/
int RaRsaPubKeyToByteArray(struct RaRsaKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen);

#ifdef __cplusplus
}
#endif


#endif
