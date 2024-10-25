#include <stdio.h>
#include <stdlib.h>
#include <racrypt.h>
#include "bnprint.h"
int main(int argc, char **argv)
{
#define PI_LEN		(4172 * 8)
#define BN_LEN		(PI_LEN + 128)
	struct RaBigNumber *pi = BnNew(BN_LEN);
	struct RaBigNumber *base5 = BnNew(BN_LEN);
	struct RaBigNumber *base239 = BnNew(BN_LEN);
	struct RaBigNumber *term = BnNew(BN_LEN);
	struct RaBigNumber *quotient = BnNew(BN_LEN);
	struct RaBigNumber *quotient5 = BnNew(BN_LEN);
	struct RaBigNumber *quotient239 = BnNew(BN_LEN);
	struct RaBigNumber *remainder = BnNew(BN_LEN);
	struct RaBigNumber *index = BnNew(BN_LEN);
	struct RaBigNumber *power5 = BnNew(BN_LEN);
	struct RaBigNumber *power239 = BnNew(BN_LEN);
	char *buffer = NULL;
	char ch;
	int offset;
	int i;

	// calculate pi using "Binary splitting of the arctan series in Machin's formula"
	// pi/4 = 4 * arctan(1/5)-arctan(1/239)
	// arctan(x) = sigma((((-1)**n)/(2n+1))*(x**(2n+1)))
	//
	// pi = 16 * arctan(1/5) - 4 * arctan(1/239)
	// = 16 * sigma((((-1) ** n) / (2n + 1)) * ((1 / 5) * *(2n + 1))) - 4 * sigma((((-1) ** n) / (2n + 1)) * ((1 / 239) ** (2n + 1)))
	// = sigma(((-1) ** n) * ((4 * ((1 / 5) ** (2n + 1))) - 16 * ((1 / 239) ** (2n + 1))) / (2n + 1))
	//
	// power5 = ((5) ** (2n + 1))
	// power239 = ((239) ** (2n + 1))
	// index = (2n + 1)
	// base5 = 16 << PI_LEN
	// base239 = 4 << PI_LEN
	// pi << PI_LEN = sigma(((-1) ** n) * (base5 / power5 - base239 / power239) / index)

	BnSetInt(base5, 16);
	BnShiftL(base5, PI_LEN);
	BnSetInt(base239, 4);
	BnShiftL(base239, PI_LEN);
	BnSetUInt(power5, 5);
	BnSetUInt(power239, 239);

	BnSetUInt(index, 1);

	for (; ; ) {
		BnDiv(quotient5, remainder, base5, power5);
		BnDiv(quotient239, remainder, base239, power239);

		BnSub(term, quotient5, quotient239);
		BnDiv(quotient, remainder, term, index);

		_BnAddR(pi, quotient);

		BnAddUInt(index, 2);
		BnMulUInt(power5, 5 * 5);
		if (BnCmp(power5, base5) > 0)
			break;
		if (BnCmp(power239, base239) <= 0)
			BnMulUInt(power239, 239 * 239);

		//////////////////

		BnDiv(quotient5, remainder, base5, power5);
		BnDiv(quotient239, remainder, base239, power239);

		BnSub(term, quotient5, quotient239);
		BnDiv(quotient, remainder, term, index);

		_BnSubR(pi, quotient);

		BnAddUInt(index, 2);
		BnMulUInt(power5, 5 * 5);
		if (BnCmp(power5, base5) > 0)
			break;
		if (BnCmp(power239, base239) <= 0)
			BnMulUInt(power239, 239 * 239);
	}

	//BnPrintLn(pi);
	offset = BnSPrint(pi, NULL, 0);

	buffer = malloc(offset * sizeof(char));
	BnSPrint(pi, buffer, offset);
	offset = 0;

	while (buffer[offset] == '0')
		offset++;
	offset++;	// skip integer part(=3)

	printf("static const uint32_t bf_P[18] = {\n\t");
	for (i = 0; i < 18; i++) {
		ch = buffer[offset + 8];
		buffer[offset + 8] = '\0';
		if (i == 17)
			printf("0x%s\n};\n", buffer + offset);
		else if (i % 8 == 7)
			printf("0x%s,\n\t", buffer + offset);
		else
			printf("0x%s, ", buffer + offset);
		buffer[offset + 8] = ch;
		offset += 8;
	}

	printf("static const uint32_t bf_S[4][256] = {\n\t{\n\t");
	for (i = 0; i < 1024; i++) {
		ch = buffer[offset + 8];
		buffer[offset + 8] = '\0';
		if (i == 1023)
			printf("0x%s\n\t}\n};\n", buffer + offset);
		else if (i % 256 == 255)
			printf("0x%s\n\t},\n\t{\n\t", buffer + offset);
		else if (i % 8 == 7)
			printf("0x%s,\n\t", buffer + offset);
		else
			printf("0x%s, ", buffer + offset);
		buffer[offset + 8] = ch;
		offset += 8;
	}

	BnFree(pi);
	BnFree(base5);
	BnFree(base239);
	BnFree(term);
	BnFree(quotient);
	BnFree(quotient5);
	BnFree(quotient239);
	BnFree(remainder);
	BnFree(index);
	BnFree(power5);
	BnFree(power239);
	free(buffer);
	return 0;
}
