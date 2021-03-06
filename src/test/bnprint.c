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
		printf("%08x", bn->data[i]);
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
	assert(bufferlen >= (bn->length * 8 + 1));

	offset = 0;
	if (bn->sign && !BN_ISZERO(bn)) {
		assert(bufferlen >= (bn->length * 8 + 2));
		if (buffer != NULL && bufferlen > 1)
			buffer[0] = '-';
		offset++;
	}
	if (buffer == NULL) {
		return bn->length * 8 + offset + 1;
	}

	if (bufferlen < bn->length * 8 + offset + 1) {
		return RA_ERR_OUT_OF_BUFFER;
	}

	for (i = bn->length - 1; i >= 0; i--)
	{
		snprintf(buffer + offset, (size_t)bufferlen - offset, "%08x", bn->data[i]);
		offset += 8;
	}
	buffer[offset] = '\0';

	return offset;
}

// max_dec_digit = log10(16^max_hex_digit) = max_hex_digit * log10(16)
// max_dec_word = max_dec_digit / 9		(needed one word for 9 digit)
#define BN_MAX_DEC_LEN(word_len)		(int)((word_len)*8*1.204120 / 9 + 1)		// 1.204120 = log10(16)

void BnPrint10(struct RaBigNumber* bn)
{
	struct RaBigNumber* bn2;
	uint32_t* decimal;
	int i;

	decimal = malloc(sizeof(uint32_t) * BN_MAX_DEC_LEN((size_t)bn->length));
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

	printf("%u", decimal[i]);
	while (--i >= 0) {
		printf("%09u", decimal[i]);
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
	uint32_t* decimal;
	int i;
	int offset;
	char temp[11];

	decimal = malloc(sizeof(uint32_t) * BN_MAX_DEC_LEN((size_t)bn->length));
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

	snprintf(temp, sizeof(temp), "%u", decimal[i]);
	offset = (int)strlen(temp);

	if (bufferlen < offset + i * 9 + 1) {
		assert(0);
		result = RA_ERR_OUT_OF_BUFFER;
		goto _EXIT;
	}
	strncpy(buffer, temp, (size_t)offset);

	while (--i >= 0) {
		snprintf(buffer + offset, (size_t)bufferlen - offset, "%09u", decimal[i]);
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
