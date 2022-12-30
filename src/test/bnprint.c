/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void BnPrint(struct RaBigNumber* bn)
{
	int i;

	if (bn->sign && !BN_ISZERO(bn))
		printf("-");

	for (i = bn->length - 1; i >= 0; i--) {
#if BN_WORD_BYTE == 8
		printf("%08x", (uint32_t)(bn->data[i] >> 32));
#endif
		printf("%08x", (uint32_t)bn->data[i]);
	}
}

void BnPrintLn(struct RaBigNumber* bn)
{
	BnPrint(bn);
	printf("\n");
}

int BnSPrint(struct RaBigNumber* bn, char* buffer, int bufferlen)
{
	int i;
	int offset;

	assert(buffer == NULL || bufferlen >= (bn->length * sizeof(bn_uint_t) * 2 + 1));

	offset = 0;
	if (bn->sign && !BN_ISZERO(bn)) {
		assert(buffer == NULL || bufferlen >= (bn->length * sizeof(bn_uint_t) * 2 + 2));
		if (buffer != NULL && bufferlen > 1)
			buffer[0] = '-';
		offset++;
	}

	if (buffer == NULL) {
		return bn->length * sizeof(bn_uint_t) * 2 + offset + 1;
	}

	if (bufferlen < bn->length * 8 + offset + 1) {
		return RA_ERR_OUT_OF_BUFFER;
	}

	for (i = bn->length - 1; i >= 0; i--)
	{
#if BN_WORD_BYTE == 8
		snprintf(buffer + offset, (size_t)bufferlen - offset, "%08x", (uint32_t)(bn->data[i] >> 32));
		offset += 8;
#endif
		snprintf(buffer + offset, (size_t)bufferlen - offset, "%08x", (uint32_t)bn->data[i]);
		offset += 8;
	}
	buffer[offset] = '\0';

	return offset;
}

// max_dec_digit = log10(16^max_hex_digit) = max_hex_digit * log10(16)
// max_dec_word = max_dec_digit / 9		(needed one word for 9 digit)
#if BN_WORD_BYTE == 8
#define BN_MAX_DEC_LEN(word_len)		(int)((word_len)*16*1.204120 / 9 + 1)		// 1.204120 = log10(16)
#else
#define BN_MAX_DEC_LEN(word_len)		(int)((word_len)*8*1.204120 / 9 + 1)		// 1.204120 = log10(16)
#endif

void BnPrint10(struct RaBigNumber* bn)
{
	struct RaBigNumber* bn2;
	bn_uint_t* decimal;
	int i;

	decimal = malloc(sizeof(bn_uint_t) * BN_MAX_DEC_LEN((size_t)bn->length));
	bn2 = BnClone(bn);
	if (decimal == NULL || bn2 == NULL) {
		printf("<mem alloc error>\n");
		goto _EXIT;
	}

	i = 0;
	do {
		BnDivInt(bn2, 1000000000, &decimal[i++]);
	} while (!BN_ISZERO(bn2));

	i--;

	if (bn->sign && !BN_ISZERO(bn))
		printf("-");

	printf("%u", (uint32_t)decimal[i]);
	while (--i >= 0) {
		printf("%09u", (uint32_t)decimal[i]);
	}

_EXIT:
	BN_SAFEFREE(bn2);
	if (decimal != NULL)
		free(decimal);
}

void BnPrint10Ln(struct RaBigNumber* bn)
{
	BnPrint10(bn);
	printf("\n");
}

int BnSPrint10(struct RaBigNumber* bn, char* buffer, int bufferlen)
{
	int result;
	struct RaBigNumber* bn2;
	bn_uint_t* decimal;
	int i;
	int offset;
	char temp[11];

	decimal = malloc(sizeof(bn_uint_t) * BN_MAX_DEC_LEN((size_t)bn->length));
	bn2 = BnClone(bn);
	if (decimal == NULL || bn2 == NULL) {
		result = RA_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	i = 0;
	do {
		BnDivInt(bn2, 1000000000, &decimal[i++]);
	} while (!BN_ISZERO(bn2));

	i--;

	offset = 0;
	if (bn->sign && !BN_ISZERO(bn)) {
		temp[0] = '-';
		offset++;
	}

	snprintf(temp, sizeof(temp), "%u", (uint32_t)decimal[i]);
	offset = (int)strlen(temp);

	if (bufferlen < offset + i * 9 + 1) {
		assert(0);
		result = RA_ERR_OUT_OF_BUFFER;
		goto _EXIT;
	}
	memcpy(buffer, temp, (size_t)offset);

	while (--i >= 0) {
		snprintf(buffer + offset, (size_t)bufferlen - offset, "%09u", (uint32_t)decimal[i]);
		offset += 9;
	}
	buffer[offset] = '\0';

	result = RA_ERR_SUCCESS;

_EXIT:
	BN_SAFEFREE(bn2);
	if (decimal != NULL)
		free(decimal);

	return result;
}
