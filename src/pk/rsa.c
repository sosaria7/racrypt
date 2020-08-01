/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "asn1.h"
#include <racrypt.h>

struct RSAKeyPair {
	struct BigNumber *mod;		// n
	struct BigNumber *pub;		// e
	struct BigNumber *priv;		// d
	struct BigNumber *prime1;	// p
	struct BigNumber *prime2;	// q
	struct BigNumber *exp1;		// d mod (p-1)
	struct BigNumber *exp2;		// d mod (q-1)
	struct BigNumber *coeff;	// (inverse of q) mod p
	struct MontCtx *mont;
};

int RSACreateKeyPair(int bit, /*out*/struct RSAKeyPair** keyPair) {
	int result;
	struct RSAKeyPair *key = NULL;
	struct BigNumber *phi = NULL;
	uint32_t seed;

	assert((bit % 2) == 0);

	key = (struct RSAKeyPair*)malloc(sizeof(struct RSAKeyPair));
	if (key == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	key->mod = BnNew(bit);
	key->pub = BnNew(32);
	key->priv = BnNew(bit);
	key->prime1 = BnNew(bit/2);
	key->prime2 = BnNew(bit/2);
	key->exp1 = BnNew(bit*2);
	key->exp2 = BnNew(bit*2);
	key->coeff = BnNew(bit);
	key->mont = NULL;
	phi = BnNew(bit);

	if (key->mod == NULL ||
		key->pub == NULL ||
		key->priv == NULL ||
		key->prime1 == NULL ||
		key->prime2 == NULL ||
		key->exp1 == NULL ||
		key->exp2 == NULL ||
		key->coeff == NULL ||
		phi == NULL)
	{
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	BnSetUInt(key->pub, 65537);

	seed = 0;
	do {
		result = GenPrimeNumberEx( key->prime1, bit / 2, NULL, NULL, &seed );
		if (result != BN_ERR_SUCCESS) goto _EXIT;

		do {
			result = GenPrimeNumberEx( key->prime2, bit / 2, NULL, NULL, &seed );
			if (result != BN_ERR_SUCCESS) goto _EXIT;
		} while ( BnCmp( key->prime1, key->prime2 ) == 0 );

		BnMul(key->mod, key->prime1, key->prime2);
	} while(BnGetBitLength(key->mod) != bit);

	BnSubInt(key->prime1, 1);
	BnSubInt(key->prime2, 1);
	BnMul(phi, key->prime1, key->prime2);
	result = GetGCDEx(NULL, key->priv, NULL, key->pub, phi, 1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;
	
	//*
	result = BnMod(key->exp1, key->priv, key->prime1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;
	result = BnMod(key->exp2, key->priv, key->prime2);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	BnAddInt(key->prime1, 1);
	BnAddInt(key->prime2, 1);
	result = GetGCDEx(NULL, key->coeff, NULL, key->prime2, key->prime1, 1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;
	//*/

	result = MontCreate(key->mod, &key->mont);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	*keyPair = key;
	key = NULL;

	result = BN_ERR_SUCCESS;

_EXIT:
	BN_SAFEFREE(phi);
	if (key != NULL) {
		RSADestroyKeyPair(key);
	}
	return result;
}

void RSADestroyKeyPair(struct RSAKeyPair *key)
{
	if (key == NULL) {
		return;
	}
	if (key->mod != NULL) {
		BnClearFree(key->mod);
	}
	if (key->pub != NULL) {
		BnClearFree(key->pub);
	}
	if (key->priv != NULL) {
		BnClearFree(key->priv);
	}
	if (key->prime1 != NULL) {
		BnClearFree(key->prime1);
	}
	if (key->prime2 != NULL) {
		BnClearFree(key->prime2);
	}
	if (key->exp1 != NULL) {
		BnClearFree(key->exp1);
	}
	if (key->exp2 != NULL) {
		BnClearFree(key->exp2);
	}
	if (key->coeff != NULL) {
		BnClearFree(key->coeff);
	}
	if (key->mont != NULL) {
		MontDestroy(key->mont);
	}
	memset(key, 0, sizeof(struct RSAKeyPair));
	free(key);
}

int RSAEncrypt(struct RSAKeyPair* key, struct BigNumber *message, /*out*/struct BigNumber *secure)
{
	int result;
	result = MontExpMod(key->mont, secure, message, key->pub);
	return result;
}

int RSADecrypt(struct RSAKeyPair* key, struct BigNumber *secure, /*out*/struct BigNumber *message)
{
	int result;
	if (key->priv == NULL)
		return BN_ERR_INVALID_DATA;
	result = MontExpMod(key->mont, message, secure, key->priv);
	return result;
}

int RSASign( struct RSAKeyPair* key, struct BigNumber *message, /*out*/struct BigNumber *secure )
{
	int result;
	if ( key->priv == NULL )
		return BN_ERR_INVALID_DATA;
	result = MontExpMod( key->mont, secure, message, key->priv );
	return result;
}

int RSAVerify(struct RSAKeyPair* key, struct BigNumber *secure, struct BigNumber *message)
{
	int result;
	struct BigNumber *decrypted;

	decrypted = BnNewW(key->mod->length);
	if (decrypted == NULL)
		return BN_ERR_OUT_OF_MEMORY;

	MontExpMod(key->mont, decrypted, secure, key->pub);
	result = BnCmp(message, decrypted);

	BnFree(decrypted);

	if (result == 0)
		return BN_ERR_SUCCESS;	// validated
	return BN_ERR_INVALID_DATA;
}

int RSAKeyBitLength( struct RSAKeyPair* key )
{
	return BnGetBitLength( key->mod );
}

#define CHECK_KEY_DATA(cond)		if (!(cond)) { result = BN_ERR_INVALID_DATA; goto _EXIT; }

static int RSAVerifyKey(struct RSAKeyPair *key)
{
	int result;
	struct BigNumber *temp = NULL;
	struct BigNumber *phi = NULL;
	struct BigNumber *prime1Sub1 = NULL;
	struct BigNumber *prime2Sub1 = NULL;
	int bit;

	CHECK_KEY_DATA(BnCmp(key->pub, key->mod) < 0);

	if (key->priv == NULL) {
		result = BN_ERR_SUCCESS;
		goto _EXIT;
	}

	bit = BnGetBitLength(key->mod);
	temp = BnNew(bit);
	phi = BnNew(bit);

	CHECK_KEY_DATA(BnGetBitLength(key->prime1) + BnGetBitLength(key->prime2) == bit);

	result = IsPrimeNumber(key->prime1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = IsPrimeNumber(key->prime2);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	BnMul(temp, key->prime1, key->prime2);
	CHECK_KEY_DATA(BnCmp(temp, key->mod) == 0);

	prime1Sub1 = BnClone(key->prime1);
	prime2Sub1 = BnClone(key->prime2);
	if (prime1Sub1 == NULL || prime2Sub1 == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	BnSubInt(prime1Sub1, 1);
	BnSubInt(prime2Sub1, 1);

	BnMul(phi, prime1Sub1, prime2Sub1);

	result = GetGCDEx(NULL, temp, NULL, key->pub, phi, 1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	CHECK_KEY_DATA(BnCmp(temp, key->priv) == 0);

	result = BnMod(temp, key->priv, prime1Sub1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	CHECK_KEY_DATA(BnCmp(temp, key->exp1) == 0);

	result = BnMod(temp, key->priv, prime2Sub1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	CHECK_KEY_DATA(BnCmp(temp, key->exp2) == 0);

	result = GetGCDEx(NULL, temp, NULL, key->prime2, key->prime1, 1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	CHECK_KEY_DATA(BnCmp(temp, key->coeff) == 0);

	result = BN_ERR_SUCCESS;

_EXIT:
	BN_SAFEFREE(temp);
	BN_SAFEFREE(phi);
	BN_SAFEFREE(prime1Sub1);
	BN_SAFEFREE(prime2Sub1);

	return result;
}

static int RSANewASN1Integer(const uint8_t *asn1Data, struct ASN1Node *node, /*out*/struct BigNumber **bnp)
{
	int result;
	struct BigNumber *bn = NULL;
	int bit;

	if (node->type != ASN1_OBJ_INTEGER) {
		result = BN_ERR_INVALID_DATA;
		goto _EXIT;
	}
	bit = node->dataLength * 8;
	if (asn1Data[node->dataOffset] == 0x00 || asn1Data[node->dataOffset] == 0xff) {
		bit -= 8;
	}

	bn = BnNew(bit);
	if (bn == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	result = BnSetByteArray(bn, asn1Data + node->dataOffset, node->dataLength);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	*bnp = bn;
	bn = NULL;

	result = BN_ERR_SUCCESS;
_EXIT:

	if (bn != NULL)
		BnFree(bn);

	return result;
}

// pkcs#1 public key
int RSACreateKeyPub(const uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp)
{
	int result;
	struct RSAKeyPair *key;
	struct ASN1Ctx *ctx = NULL;
	struct ASN1Node *cur;

	key = (struct RSAKeyPair *)malloc(sizeof(struct RSAKeyPair));
	if (key == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	memset(key, 0, sizeof(struct RSAKeyPair));

	result = ASN1CreateContext(asn1Data, dataLen, &ctx);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = ASN1GetRoot(ctx, &cur);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->child;
	result = RSANewASN1Integer(asn1Data, cur, &key->mod);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->next;
	result = RSANewASN1Integer(asn1Data, cur, &key->pub);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = MontCreate(key->mod, &key->mont);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = RSAVerifyKey(key);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	*keyp = key;
	key = NULL;
	result = BN_ERR_SUCCESS;
_EXIT:
	if (ctx != NULL)
		ASN1DestroyContext(ctx);
	if (key != NULL)
		RSADestroyKeyPair(key);

	return result;
}


// pkcs#1 private key
int RSACreateKeyPriv(const uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp)

{
	int result;
	struct RSAKeyPair *key;
	struct ASN1Ctx *ctx = NULL;
	struct ASN1Node *cur;

	key = (struct RSAKeyPair *)malloc(sizeof(struct RSAKeyPair));
	if (key == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	memset(key, 0, sizeof(struct RSAKeyPair));

	result = ASN1CreateContext(asn1Data, dataLen, &ctx);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = ASN1GetRoot(ctx, &cur);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->child;
	cur = cur->next;		// skip version

	result = RSANewASN1Integer(asn1Data, cur, &key->mod);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->next;
	result = RSANewASN1Integer(asn1Data, cur, &key->pub);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->next;
	result = RSANewASN1Integer(asn1Data, cur, &key->priv);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->next;
	result = RSANewASN1Integer(asn1Data, cur, &key->prime1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->next;
	result = RSANewASN1Integer(asn1Data, cur, &key->prime2);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->next;
	result = RSANewASN1Integer(asn1Data, cur, &key->exp1);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->next;
	result = RSANewASN1Integer(asn1Data, cur, &key->exp2);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->next;
	result = RSANewASN1Integer(asn1Data, cur, &key->coeff);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = MontCreate(key->mod, &key->mont);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = RSAVerifyKey(key);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	*keyp = key;
	key = NULL;
	result = BN_ERR_SUCCESS;
_EXIT:
	if (ctx != NULL)
		ASN1DestroyContext(ctx);
	if (key != NULL)
		RSADestroyKeyPair(key);

	return result;
}

#define OID_RSA_Encryption		"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"		// 1.2.840.113549.1.1.1
#define IS_OID(data, node, oid)		((node)->type == ASN1_OBJ_IDENTIFIER && memcmp((uint8_t*)data+(node)->dataOffset, oid, sizeof(oid)-1) == 0)


// pkcs#8, byte array = BER
int RSACreateKeyFromByteArray(const uint8_t *asn1Data, int dataLen, /*out*/struct RSAKeyPair** keyp)
{
	int result;
	struct ASN1Ctx *ctx = NULL;
	struct ASN1Node *cur;
	int isPrivate = 0;

	result = ASN1CreateContext(asn1Data, dataLen, &ctx);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	result = ASN1GetRoot(ctx, &cur);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	cur = cur->child;
	if (cur->type == ASN1_OBJ_INTEGER) {	// version
		isPrivate = 1;
		cur = cur->next;
	}
	if (!IS_OID(asn1Data, cur->child, OID_RSA_Encryption)) {
		result = BN_ERR_INVALID_DATA;
		goto _EXIT;
	}
	cur = cur->next;

	if (isPrivate) {	// private key
		if (cur->type != ASN1_OBJ_OCTET_STRING) {
			result = BN_ERR_INVALID_DATA;
			goto _EXIT;
		}
		result = RSACreateKeyPriv(asn1Data + cur->dataOffset, cur->dataLength, keyp);
		if (result != BN_ERR_SUCCESS) goto _EXIT;
	}
	else {		// public key
		if (cur->type != ASN1_OBJ_BIT_STRING) {
			result = BN_ERR_INVALID_DATA;
			goto _EXIT;
		}
		// unused bit should be 0
		if (cur->dataLength < 2 || asn1Data[cur->dataOffset] != 0) {
			result = BN_ERR_INVALID_DATA;
			goto _EXIT;
		}
		result = RSACreateKeyPub(asn1Data + cur->dataOffset + 1, cur->dataLength - 1, keyp);
		if (result != BN_ERR_SUCCESS) goto _EXIT;
	}

	result = BN_ERR_SUCCESS;
_EXIT:

	if (ctx != NULL)
		ASN1DestroyContext(ctx);

	return result;
}

static int ASN1EncodeLength(uint32_t len, uint8_t *buffer, int bufferlen)
{
	int ret;
	uint8_t temp[5];

	if (len < 0x80) {
		temp[0] = (uint8_t)len;
		ret = 1;
	}
	else if (len < 0x100) {
		temp[0] = 0x81;
		temp[1] = (uint8_t)len;
		ret = 2;
	}
	else if (len < 0x10000) {
		temp[0] = 0x82;
		temp[1] = (uint8_t)(len >> 8);
		temp[2] = (uint8_t)len;
		ret = 3;
	}
	else if (len < 0x1000000) {
		temp[0] = 0x83;
		temp[1] = (uint8_t)(len >> 16);
		temp[2] = (uint8_t)(len >> 8);
		temp[3] = (uint8_t)len;
		ret = 4;
	}
	else {
		temp[0] = 0x84;
		temp[1] = (uint8_t)(len >> 24);
		temp[2] = (uint8_t)(len >> 16);
		temp[3] = (uint8_t)(len >> 8);
		temp[4] = (uint8_t)len;
		ret = 5;
	}
	if (buffer != NULL) {
		if (bufferlen >= ret) {
			memcpy(buffer, temp, ret);
		}
		else {
			ret = 0;		// error
		}
	}
	return ret;
}

static const uint8_t rsakeyHeader[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
};
static const uint8_t rsakeyVersion[] = {
	0x02, 0x01, 0x00
};

int RSAPrivKeyToByteArray(struct RSAKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen)
{
	int result;
	uint8_t *buffer = NULL;
	uint8_t *temp = NULL;
	int bufferlen;
	int offset;
	int bit;
	int bytelen;
	int len;
	bit = BnGetBitLength(key->mod);
	bytelen = bit * 8 + 1;	// max

	if (key->priv == NULL) {
		result = BN_ERR_INVALID_DATA;
		goto _EXIT;
	}
	temp = (uint8_t*)malloc(bytelen);
	if (temp == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	// calculate the maximum size of output data
	bufferlen = (bytelen + ASN1EncodeLength(bytelen, NULL, 0) + 1) * 8;		// eight integer
	bufferlen += 3;												// version
	bufferlen += ASN1EncodeLength(bufferlen, NULL, 0) + 1;		// sequence
	bufferlen += ASN1EncodeLength(bufferlen, NULL, 0) + 1;		// octet string
	bufferlen += sizeof(rsakeyHeader) + sizeof(rsakeyVersion);
	bufferlen += ASN1EncodeLength(bufferlen, NULL, 0) + 1;		// sequence
	buffer = (uint8_t*)malloc(bufferlen);
	if (buffer == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	offset = bufferlen;

	// coefficient
	len = BnToByteArray(key->coeff, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// exponent2
	len = BnToByteArray(key->exp2, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// exponent1
	len = BnToByteArray(key->exp1, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// prime2
	len = BnToByteArray(key->prime2, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// prime1
	len = BnToByteArray(key->prime1, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// privateExponent
	len = BnToByteArray(key->priv, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// publicExponent
	len = BnToByteArray(key->pub, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// publicExponent
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// modulus
	len = BnToByteArray(key->mod, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// modulus
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// version
	offset -= sizeof(rsakeyVersion);
	memcpy(buffer + offset, rsakeyVersion, sizeof(rsakeyVersion));		// version

	// SEQUENCE
	len = ASN1EncodeLength(bufferlen - offset, temp, len);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_SEQUENCE;

	// OCTET_STRING
	len = ASN1EncodeLength(bufferlen - offset, temp, len);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_OCTET_STRING;

	// header
	offset -= sizeof(rsakeyHeader);
	memcpy(buffer + offset, rsakeyHeader, sizeof(rsakeyHeader));

	// version
	offset -= sizeof(rsakeyVersion);
	memcpy(buffer + offset, rsakeyVersion, sizeof(rsakeyVersion));		// version

		// SEQUENCE
	len = ASN1EncodeLength(bufferlen - offset, temp, len);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_SEQUENCE;

	len = bufferlen - offset;

	if (asn1Data != NULL) {
		if (dataLen < len) {
			result = BN_ERR_OUT_OF_BUFFER;
			goto _EXIT;
		}
		memcpy(asn1Data, buffer + offset, bufferlen - offset);
	}
	if (resultLen != NULL) {
		*resultLen = len;
	}

	result = BN_ERR_SUCCESS;
_EXIT:
	if (buffer != NULL)
		free(buffer);
	if (temp != NULL)
		free(temp);

	return result;
}

int RSAPubKeyToByteArray(struct RSAKeyPair* key, /*out*/uint8_t *asn1Data, int dataLen, /*out*/int *resultLen)
{
	int result;
	uint8_t *buffer = NULL;
	uint8_t *temp = NULL;
	int bufferlen;
	int offset;
	int bit;
	int bytelen;
	int len;
	bit = BnGetBitLength(key->mod);
	bytelen = bit * 8 + 1;	// max

	temp = (uint8_t*)malloc(bytelen);
	if (temp == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	// calculate the maximum size of output data
	bufferlen = (bytelen + ASN1EncodeLength(bytelen, NULL, 0) + 1) * 2;		// two integer
	bufferlen += ASN1EncodeLength(bufferlen, NULL, 0) + 1;		// sequence
	bufferlen += ASN1EncodeLength(bufferlen + 1, NULL, 0) + 2;	// bit string
	bufferlen += sizeof(rsakeyHeader);
	bufferlen += ASN1EncodeLength(bufferlen, NULL, 0) + 1;		// sequence
	buffer = (uint8_t*)malloc(bufferlen);
	if (buffer == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	offset = bufferlen;

	// publicExponent
	len = BnToByteArray(key->pub, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// publicExponent
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// modulus
	len = BnToByteArray(key->mod, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// modulus
	len = ASN1EncodeLength(len, temp, bytelen);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_INTEGER;

	// SEQUENCE
	len = ASN1EncodeLength(bufferlen - offset, temp, len);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_SEQUENCE;

	// BIT_STRING
	offset--;
	buffer[offset] = 0;		// unused bits = 0
	len = ASN1EncodeLength(bufferlen - offset, temp, len);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_BIT_STRING;

	// header
	offset -= sizeof(rsakeyHeader);
	memcpy(buffer + offset, rsakeyHeader, sizeof(rsakeyHeader));

	// SEQUENCE
	len = ASN1EncodeLength(bufferlen - offset, temp, len);
	offset -= len;
	memcpy(buffer + offset, temp, len);		// length
	offset--;
	buffer[offset] = ASN1_OBJ_SEQUENCE;

	len = bufferlen - offset;

	if (asn1Data != NULL) {
		if (dataLen < len) {
			result = BN_ERR_OUT_OF_BUFFER;
			goto _EXIT;
		}
		memcpy(asn1Data, buffer + offset, bufferlen - offset);
	}
	if (resultLen != NULL) {
		*resultLen = len;
	}

	result = BN_ERR_SUCCESS;
_EXIT:
	if (buffer != NULL)
		free(buffer);
	if (temp != NULL)
		free(temp);

	return result;
}
