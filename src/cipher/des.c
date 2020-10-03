/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdlib.h>
#include <string.h>

#include "block_cipher.h"

#define GET_UINT32_BE(b)		(uint32_t)(((b)[0] << 24)|((b)[1] << 16)|((b)[2] << 8)|(b)[3])
#define GET_UINT64_BE(b)		(((uint64_t)GET_UINT32_BE(b) << 32) | GET_UINT32_BE(b + 4))
#define PUT_UINT32_BE(b, v)		{ (b)[0] = (uint8_t)((v)>>24); (b)[1] = (uint8_t)((v)>>16); (b)[2] = (uint8_t)((v)>>8); (b)[3] = (uint8_t)(v); }
#define PUT_UINT64_BE(b, v)		{ PUT_UINT32_BE(b, (v)>>32); PUT_UINT32_BE(b + 4, v); }
#define RL28(X, n)	((X << n) | (X >> (28 - n)))

// The lookup tables are generated by the following source code
/*
#include <stdio.h>
#include <stdint.h>

#define PT(bit)				(32-bit)
#define PERMUTE(m,n)		(m & ((uint32_t)1 << n))
typedef uint8_t				pt_t;

// Straight Permutation Table
static const pt_t perm[32] = {
	PT(16), PT(7) , PT(20), PT(21),	PT(29), PT(12), PT(28), PT(17),
	PT(1) , PT(15), PT(23), PT(26),	PT(5) , PT(18), PT(31), PT(10),
	PT(2) , PT(8) , PT(24), PT(14),	PT(32), PT(27), PT(3) , PT(9) ,
	PT(19), PT(13), PT(30), PT(6) ,	PT(22), PT(11), PT(4) , PT(25)
};

static const pt_t perm_key1[32] = {
	PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(1),
	PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(2),
	PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(3),
	PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(4)
};

static const pt_t perm_key2[32] = {
	PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(3),
	PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(2),
	PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(1),
	PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32), PT(32)
};

#define NUMOF_PT(pt)	sizeof(pt) / sizeof(pt[0])

// S-box Table
static const int sbox[8][64] = {
	{
		14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
		4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0
	},
	{
		15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
		0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9
	},
	{
		10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
		13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12
	},
	{
		7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
		10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14
	},
	{
		2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
		4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3
	},
	{
		12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
		9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13
	},
	{
		4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
		1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12
	},
	{
		13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
		7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11
	}
};

static uint32_t permute(uint32_t input, const pt_t *table, int size)
{
	int i;
	uint32_t output = 0;
	for (i = 0; i < size; i++) {
		output <<= 1;
		output |= (PERMUTE(input, table[i]) != 0);
	}
	output = output << (32 - size);
	return output;
}

static void printTable(int table)
{
	int i;
	uint32_t data;
	int shift;

	shift = 32 - ((table+1)*4);
	data = 0;
	for (i = 0; i < 64; i++) {

		data = sbox[table][i];
		data <<= shift;
		data = permute(data, perm, NUMOF_PT(perm));

		if (i == 63)
			printf("0x%08x\n", data);
		else if ((i % 8) == 7)
			printf("0x%08x,\n\t", data);
		else
			printf("0x%08x, ", data);
	}
}

static void printKeyTable1()
{
	int i;
	uint32_t data;
	int shift;

	printf("static const uint32_t des_key_lookup1[16] = {\n\t");

	shift = 32 - 4;
	data = 0;
	for (i = 0; i < 16; i++) {
		data = i << shift;
		data = permute(data, perm_key1, NUMOF_PT(perm_key1));

		if (i == 15)
			printf("0x%08x\n", data);
		else if ((i % 8) == 7)
			printf("0x%08x,\n\t", data);
		else
			printf("0x%08x, ", data);
	}
	printf("};\n");
}

static void printKeyTable2()
{
	int i;
	uint32_t data;
	int shift;

	printf("static const uint32_t des_key_lookup2[8] = {\n\t");

	shift = 32 - 3;
	data = 0;
	for (i = 0; i < 8; i++) {
		data = i << shift;
		data = permute(data, perm_key2, NUMOF_PT(perm_key2));

		if (i == 7)
			printf("0x%08x\n", data);
		else
			printf("0x%08x, ", data);
	}
	printf("};\n");
}


int main()
{
	int i;
	printf("static const uint32_t des_lookup[8][64] = {\n");
	for (i = 0; i < 8; i++) {
		printf("\t{\n\t");
		printTable(i);
		if (i == 7)
			printf("\t}\n");
		else
			printf("\t},\n");
	}

	printf("};\n");

	printKeyTable1();
	printKeyTable2();

	return 0;
}
*/

static const uint32_t des_lookup[8][64] = {
	{
	0x00808200, 0x00000000, 0x00008000, 0x00808202, 0x00808002, 0x00008202, 0x00000002, 0x00008000,
	0x00000200, 0x00808200, 0x00808202, 0x00000200, 0x00800202, 0x00808002, 0x00800000, 0x00000002,
	0x00000202, 0x00800200, 0x00800200, 0x00008200, 0x00008200, 0x00808000, 0x00808000, 0x00800202,
	0x00008002, 0x00800002, 0x00800002, 0x00008002, 0x00000000, 0x00000202, 0x00008202, 0x00800000,
	0x00008000, 0x00808202, 0x00000002, 0x00808000, 0x00808200, 0x00800000, 0x00800000, 0x00000200,
	0x00808002, 0x00008000, 0x00008200, 0x00800002, 0x00000200, 0x00000002, 0x00800202, 0x00008202,
	0x00808202, 0x00008002, 0x00808000, 0x00800202, 0x00800002, 0x00000202, 0x00008202, 0x00808200,
	0x00000202, 0x00800200, 0x00800200, 0x00000000, 0x00008002, 0x00008200, 0x00000000, 0x00000000
	},
	{
	0x40084010, 0x40004000, 0x00004000, 0x00084010, 0x00080000, 0x00000010, 0x40080010, 0x40004010,
	0x40000010, 0x40084010, 0x40084000, 0x40000000, 0x40004000, 0x00080000, 0x00000010, 0x40080010,
	0x00084000, 0x00080010, 0x40004010, 0x00000000, 0x40000000, 0x00004000, 0x00084010, 0x40080000,
	0x00080010, 0x40000010, 0x00000000, 0x00084000, 0x00004010, 0x40084000, 0x40080000, 0x00004010,
	0x00000000, 0x00084010, 0x40080010, 0x00080000, 0x40004010, 0x40080000, 0x40084000, 0x00004000,
	0x40080000, 0x40004000, 0x00000010, 0x40084010, 0x00084010, 0x00000010, 0x00004000, 0x40000000,
	0x00004010, 0x40084000, 0x00080000, 0x40000010, 0x00080010, 0x40004010, 0x40000010, 0x00080010,
	0x00084000, 0x00000000, 0x40004000, 0x00004010, 0x40000000, 0x40080010, 0x40084010, 0x00084000
	},
	{
	0x00000104, 0x04010100, 0x00000000, 0x04010004, 0x04000100, 0x00000000, 0x00010104, 0x04000100,
	0x00010004, 0x04000004, 0x04000004, 0x00010000, 0x04010104, 0x00010004, 0x04010000, 0x00000104,
	0x04000000, 0x00000004, 0x04010100, 0x00000100, 0x00010100, 0x04010000, 0x04010004, 0x00010104,
	0x04000104, 0x00010100, 0x00010000, 0x04000104, 0x00000004, 0x04010104, 0x00000100, 0x04000000,
	0x04010100, 0x04000000, 0x00010004, 0x00000104, 0x00010000, 0x04010100, 0x04000100, 0x00000000,
	0x00000100, 0x00010004, 0x04010104, 0x04000100, 0x04000004, 0x00000100, 0x00000000, 0x04010004,
	0x04000104, 0x00010000, 0x04000000, 0x04010104, 0x00000004, 0x00010104, 0x00010100, 0x04000004,
	0x04010000, 0x04000104, 0x00000104, 0x04010000, 0x00010104, 0x00000004, 0x04010004, 0x00010100
	},
	{
	0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x00401040, 0x80400040, 0x80400000, 0x80001000,
	0x00000000, 0x00401000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00400040, 0x80400000,
	0x80000000, 0x00001000, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x80001000, 0x00001040,
	0x80400040, 0x80000000, 0x00001040, 0x00400040, 0x00001000, 0x00401040, 0x80401040, 0x80000040,
	0x00400040, 0x80400000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00000000, 0x00401000,
	0x00001040, 0x00400040, 0x80400040, 0x80000000, 0x80401000, 0x80001040, 0x80001040, 0x00000040,
	0x80401040, 0x80000040, 0x80000000, 0x00001000, 0x80400000, 0x80001000, 0x00401040, 0x80400040,
	0x80001000, 0x00001040, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x00001000, 0x00401040
	},
	{
	0x00000080, 0x01040080, 0x01040000, 0x21000080, 0x00040000, 0x00000080, 0x20000000, 0x01040000,
	0x20040080, 0x00040000, 0x01000080, 0x20040080, 0x21000080, 0x21040000, 0x00040080, 0x20000000,
	0x01000000, 0x20040000, 0x20040000, 0x00000000, 0x20000080, 0x21040080, 0x21040080, 0x01000080,
	0x21040000, 0x20000080, 0x00000000, 0x21000000, 0x01040080, 0x01000000, 0x21000000, 0x00040080,
	0x00040000, 0x21000080, 0x00000080, 0x01000000, 0x20000000, 0x01040000, 0x21000080, 0x20040080,
	0x01000080, 0x20000000, 0x21040000, 0x01040080, 0x20040080, 0x00000080, 0x01000000, 0x21040000,
	0x21040080, 0x00040080, 0x21000000, 0x21040080, 0x01040000, 0x00000000, 0x20040000, 0x21000000,
	0x00040080, 0x01000080, 0x20000080, 0x00040000, 0x00000000, 0x20040000, 0x01040080, 0x20000080
	},
	{
	0x10000008, 0x10200000, 0x00002000, 0x10202008, 0x10200000, 0x00000008, 0x10202008, 0x00200000,
	0x10002000, 0x00202008, 0x00200000, 0x10000008, 0x00200008, 0x10002000, 0x10000000, 0x00002008,
	0x00000000, 0x00200008, 0x10002008, 0x00002000, 0x00202000, 0x10002008, 0x00000008, 0x10200008,
	0x10200008, 0x00000000, 0x00202008, 0x10202000, 0x00002008, 0x00202000, 0x10202000, 0x10000000,
	0x10002000, 0x00000008, 0x10200008, 0x00202000, 0x10202008, 0x00200000, 0x00002008, 0x10000008,
	0x00200000, 0x10002000, 0x10000000, 0x00002008, 0x10000008, 0x10202008, 0x00202000, 0x10200000,
	0x00202008, 0x10202000, 0x00000000, 0x10200008, 0x00000008, 0x00002000, 0x10200000, 0x00202008,
	0x00002000, 0x00200008, 0x10002008, 0x00000000, 0x10202000, 0x10000000, 0x00200008, 0x10002008
	},
	{
	0x00100000, 0x02100001, 0x02000401, 0x00000000, 0x00000400, 0x02000401, 0x00100401, 0x02100400,
	0x02100401, 0x00100000, 0x00000000, 0x02000001, 0x00000001, 0x02000000, 0x02100001, 0x00000401,
	0x02000400, 0x00100401, 0x00100001, 0x02000400, 0x02000001, 0x02100000, 0x02100400, 0x00100001,
	0x02100000, 0x00000400, 0x00000401, 0x02100401, 0x00100400, 0x00000001, 0x02000000, 0x00100400,
	0x02000000, 0x00100400, 0x00100000, 0x02000401, 0x02000401, 0x02100001, 0x02100001, 0x00000001,
	0x00100001, 0x02000000, 0x02000400, 0x00100000, 0x02100400, 0x00000401, 0x00100401, 0x02100400,
	0x00000401, 0x02000001, 0x02100401, 0x02100000, 0x00100400, 0x00000000, 0x00000001, 0x02100401,
	0x00000000, 0x00100401, 0x02100000, 0x00000400, 0x02000001, 0x02000400, 0x00000400, 0x00100001
	},
	{
	0x08000820, 0x00000800, 0x00020000, 0x08020820, 0x08000000, 0x08000820, 0x00000020, 0x08000000,
	0x00020020, 0x08020000, 0x08020820, 0x00020800, 0x08020800, 0x00020820, 0x00000800, 0x00000020,
	0x08020000, 0x08000020, 0x08000800, 0x00000820, 0x00020800, 0x00020020, 0x08020020, 0x08020800,
	0x00000820, 0x00000000, 0x00000000, 0x08020020, 0x08000020, 0x08000800, 0x00020820, 0x00020000,
	0x00020820, 0x00020000, 0x08020800, 0x00000800, 0x00000020, 0x08020020, 0x00000800, 0x00020820,
	0x08000800, 0x00000020, 0x08000020, 0x08020000, 0x08020020, 0x08000000, 0x00020000, 0x08000820,
	0x00000000, 0x08020820, 0x00020020, 0x08000020, 0x08020000, 0x08000800, 0x08000820, 0x00000000,
	0x08020820, 0x00020800, 0x00020800, 0x00000820, 0x00000820, 0x00020020, 0x08000000, 0x08020800
	}
};
static const uint32_t des_key_lookup1[16] = {
	0x00000000, 0x00000001, 0x00000100, 0x00000101, 0x00010000, 0x00010001, 0x00010100, 0x00010101,
	0x01000000, 0x01000001, 0x01000100, 0x01000101, 0x01010000, 0x01010001, 0x01010100, 0x01010101
};
static const uint32_t des_key_lookup2[8] = {
	0x00000000, 0x01000000, 0x00010000, 0x01010000, 0x00000100, 0x01000100, 0x00010100, 0x01010100
};

static void RaDesProcess(struct RaDesCtx *ctx, uint32_t key[2][16], uint64_t input, uint64_t *output, int is_encode)
{
	int i;

	uint32_t data_l;
	uint32_t data_r;
	uint32_t temp;
	int key_inc;
	int key_index;

	data_l = (uint32_t)(input >> 32);
	data_r = (uint32_t)input;
	// Initial permutation
	temp = ((data_l >> 4) ^ data_r) & 0x0F0F0F0F;
	data_r ^= temp;
	data_l ^= temp << 4;
	temp = ((data_l >> 16) ^ data_r) & 0x0000FFFF;
	data_r ^= temp;
	data_l ^= temp << 16;
	temp = ((data_l << 2) ^ data_r) & 0xCCCCCCCC;
	data_r ^= temp;
	data_l ^= temp >> 2;
	temp = ((data_l << 8) ^ data_r) & 0xFF00FF00;
	data_r ^= temp;
	data_l ^= temp >> 8;
	temp = ((data_l >> 1) ^ data_r) & 0x55555555;
	data_r ^= temp;
	data_l ^= temp << 1;

	if (is_encode) {
		key_index = 0;
		key_inc = 1;
	}
	else {
		key_index = 15;
		key_inc = -1;
	}
	for (i = 0; i < 16; i++) {
		temp = ((data_r >> 3) | (data_r << 29)) ^ key[0][key_index];
		data_l ^= des_lookup[0][(temp >> 24) & 0x3f];
		data_l ^= des_lookup[2][(temp >> 16) & 0x3f];
		data_l ^= des_lookup[4][(temp >> 8) & 0x3f];
		data_l ^= des_lookup[6][temp & 0x3f];

		temp = ((data_r << 1) | (data_r >> 31)) ^ key[1][key_index];
		data_l ^= des_lookup[1][(temp >> 24) & 0x3f];
		data_l ^= des_lookup[3][(temp >> 16) & 0x3f];
		data_l ^= des_lookup[5][(temp >> 8) & 0x3f];
		data_l ^= des_lookup[7][temp & 0x3f];

		key_index += key_inc;

		temp = data_l;
		data_l = data_r;
		data_r = temp;
	}

	// should not be swapped on the last round but it was, so swap again
	data_r = data_l;
	data_l = temp;

	// Final permutation
	temp = ((data_l >> 1) ^ data_r) & 0x55555555;
	data_r ^= temp;
	data_l ^= temp << 1;
	temp = ((data_l << 8) ^ data_r) & 0xFF00FF00;
	data_r ^= temp;
	data_l ^= temp >> 8;
	temp = ((data_l << 2) ^ data_r) & 0xCCCCCCCC;
	data_r ^= temp;
	data_l ^= temp >> 2;
	temp = ((data_l >> 16) ^ data_r) & 0x0000FFFF;
	data_r ^= temp;
	data_l ^= temp << 16;
	temp = ((data_l >> 4) ^ data_r) & 0x0F0F0F0F;
	data_r ^= temp;
	data_l ^= temp << 4;
	*output = ((uint64_t)data_l << 32) | data_r;
}

static void RaDesEncryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output)
{
	uint64_t data;
	struct RaDesCtx *ctx;
	ctx = CHILD_OF(blockCipher, struct RaDesCtx, blockCipher);

	data = GET_UINT64_BE(input);
	if (ctx->keyType == RA_DES) {
		RaDesProcess(ctx, ctx->round_key1, data, &data, 1);
	}
	else {
		RaDesProcess(ctx, ctx->round_key1, data, &data, 1);
		RaDesProcess(ctx, ctx->round_key2, data, &data, 0);
		RaDesProcess(ctx, ctx->round_key3, data, &data, 1);
	}
	PUT_UINT64_BE(output, data);
}

static void RaDesDecryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output)
{
	uint64_t data;
	struct RaDesCtx *ctx;
	ctx = CHILD_OF(blockCipher, struct RaDesCtx, blockCipher);

	data = GET_UINT64_BE(input);
	if (ctx->keyType == RA_DES) {
		RaDesProcess(ctx, ctx->round_key1, data, &data, 0);
	}
	else {
		RaDesProcess(ctx, ctx->round_key3, data, &data, 0);
		RaDesProcess(ctx, ctx->round_key2, data, &data, 1);
		RaDesProcess(ctx, ctx->round_key1, data, &data, 0);
	}
	PUT_UINT64_BE(output, data);
}

static void RaDesInitKey(const uint8_t *key, /*out*/uint32_t round_key[2][16])
{
	uint32_t key_l;
	uint32_t key_r;
	uint32_t temp;
	int i;

	// Parity bit drop permutation
	temp = GET_UINT32_BE(key);
	key_l = des_key_lookup1[temp >> 28] |
		(des_key_lookup1[(temp >> 20) & 0x0f] << 1) |
		(des_key_lookup1[(temp >> 12) & 0x0f] << 2) |
		(des_key_lookup1[(temp >> 4) & 0x0f] << 3);
	key_r = (des_key_lookup2[(temp >> 25) & 0x07] << 4) |
		(des_key_lookup2[(temp >> 17) & 0x07] << 5) |
		(des_key_lookup2[(temp >> 9) & 0x07] << 6) |
		(des_key_lookup2[(temp >> 1) & 0x07] << 7);

	temp = GET_UINT32_BE(key + 4);
	key_l |= (des_key_lookup1[temp >> 28] << 4) |
		(des_key_lookup1[(temp >> 20) & 0x0f] << 5) |
		(des_key_lookup1[(temp >> 12) & 0x0f] << 6) |
		(des_key_lookup1[(temp >> 4) & 0x0f] << 7);
	key_r |= des_key_lookup2[(temp >> 25) & 0x07] |
		(des_key_lookup2[(temp >> 17) & 0x07] << 1) |
		(des_key_lookup2[(temp >> 9) & 0x07] << 2) |
		(des_key_lookup2[(temp >> 1) & 0x07] << 3);

	temp = (key_l ^ (key_r >> 24)) & 0x0000000F;
	key_l ^= temp;
	key_r ^= temp << 24;
	key_r = ((key_l & 0x0000000f) << 28) |
		((key_r & 0xf0f0f000) >> 4 ) |
		((key_r & 0x000f0f00) << 4 ) |
		((key_r & 0x0f000000) >> 20);
	key_l &= 0xfffffff0;

	for (i = 0; i < 16; i++) {
		switch (i) {
		case 0: case 1: case 8: case 15:
			key_l = RL28(key_l, 1);
			key_r = RL28(key_r, 1);
			break;
		default:
			key_l = RL28(key_l, 2);
			key_r = RL28(key_r, 2);
			break;
		}
		/*
		* expand 32bit data_r to 48bit and xor with key
		*         3 0                         1                           2                               3     0
		*         2 1 2 3 4 5 4 5 6 7 8 9 8 9 0 1 2 3 2 3 4 5 6 7 6 7 8 9 0 1 0 1 2 3 4 5 4 5 6 7 8 9 8 9 0 1 2 1
		*         0                 1                   2                   3                   4
		*         1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8
		*         |----1----| |----2----| |----3----| |----4----| |----5----| |----6----| |----7----| |----8----|
		* so. splitting key into 2 parts, data_r can be xored without expanding
		*         3 0                 1                   2                   3     0
		*         2 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 1
		*         |----1----|     |----3----|     |----5----|     |----7----|
		*         |       |----2----|     |----4----|     |----6----|     |----8----|
		*
		*         0                 1                   2                   3
		*         1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
		* key[0]      |----1----|     |----3----|     |----5----|     |----7----|
		* key[1]      |----2----|     |----4----|     |----6----|     |----8----|
		* 
		* below are key selection from 24bit key_l and 24bit key_r
		* - selected bit position of key_l and key_r
		* |----1----|   key_l:  14  17  11  24  1   5
		* |----2----|   key_l:  23  19  12  4   26  8
		* |----3----|   key_r:  13  24  3   9   19  27
		* |----4----|   key_r:  16  21  11  28  6   25
		* |----5----|   key_l:  3   28  15  6   21  10
		* |----6----|   key_l:  16  7   27  20  13  2
		* |----7----|   key_r:  2   12  23  17  5   20
		* |----8----|   key_r: 18   14  22  8   1   4
		*/
		round_key[0][i] =
			((key_l & 0x80000000) >> 6 ) |
			((key_l & 0x10000000) >> 10) |
			((key_l & 0x08000000) >> 3 ) |
			((key_l & 0x01000000) >> 8 ) |
			((key_l & 0x00200000) << 6 ) |
			((key_l & 0x00100000) >> 1 ) |
			((key_l & 0x00040040) << 11) |
			((key_l & 0x00008000) << 13) |
			((key_l & 0x00002000) << 7 ) |
			((key_l & 0x00000200) << 12) |
			((key_l & 0x00000100) << 18) |
			((key_r & 0x20200000) >> 18) |
			((key_r & 0x04000000) >> 25) |
			((key_r & 0x00800000) >> 13) |
			((key_r & 0x00080000) >> 6 ) |
			((key_r & 0x00010000) >> 11) |
			((key_r & 0x00002000) >> 4 ) |
			((key_r & 0x00000880) >> 7 ) |
			((key_r & 0x00000100) << 4 ) |
			((key_r & 0x00000020) << 3 ) |
			((key_r & 0x00000010) >> 2 );
		round_key[1][i] =
			((key_l & 0x40000000) >> 14) |
			((key_l & 0x24000000) >> 0 ) |
			((key_l & 0x02000000) >> 5 ) |
			((key_l & 0x00400000) << 2 ) |
			((key_l & 0x00080000) >> 2 ) |
			((key_l & 0x00020000) << 10) |
			((key_l & 0x00010000) << 5 ) |
			((key_l & 0x00001000) << 6 ) |
			((key_l & 0x00000820) << 14) |
			((key_l & 0x00000010) << 24) |
			((key_r & 0x80000000) >> 30) |
			((key_r & 0x40000000) >> 17) |
			((key_r & 0x10000000) >> 28) |
			((key_r & 0x08000000) >> 18) |
			((key_r & 0x01000000) >> 22) |
			((key_r & 0x00100000) >> 8 ) |
			((key_r & 0x00040000) >> 14) |
			((key_r & 0x00008000) >> 5 ) |
			((key_r & 0x00004000) >> 9 ) |
			((key_r & 0x00001000) >> 4 ) |
			((key_r & 0x00000400) >> 7 ) |
			((key_r & 0x00000200) << 2 );
	}
}

void RaDesInit(struct RaDesCtx *ctx, enum RaDesKeyType keyType, const uint8_t *key, enum RaBlockCipherMode opMode)
{
	memset(ctx->iv, 0, RA_BLOCK_LEN_DES);
	RaBlockCipherInit(&ctx->blockCipher, RaDesEncryptBlock, RaDesDecryptBlock, opMode, RA_BLOCK_LEN_DES, ctx->iv, ctx->buffer);

	ctx->keyType = keyType;
	
	RaDesInitKey(key, ctx->round_key1);
	switch (keyType) {
	case RA_DES:
		memset(ctx->round_key2, 0, sizeof(ctx->round_key2));
		memset(ctx->round_key3, 0, sizeof(ctx->round_key3));
		break;
	case RA_DES_EDE2:
		RaDesInitKey(key + RA_KEY_LEN_DES, ctx->round_key2);
		memcpy(ctx->round_key3, ctx->round_key1, sizeof(ctx->round_key1));
		break;
	case RA_DES_EDE3:
	default:
		RaDesInitKey(key + RA_KEY_LEN_DES, ctx->round_key2);
		RaDesInitKey(key + RA_KEY_LEN_DES * 2, ctx->round_key3);
		break;
	}
}

int RaDesCreate(const uint8_t *key, enum RaDesKeyType keyType, enum RaBlockCipherMode opMode, struct RaDesCtx **ctxp)
{
	struct RaDesCtx* ctx;
	ctx = (struct RaDesCtx*)malloc(sizeof(struct RaDesCtx));
	if (ctx == NULL) {
		return RA_ERR_OUT_OF_MEMORY;
	}
	RaDesInit(ctx, keyType, key, opMode);

	*ctxp = ctx;

	return RA_ERR_SUCCESS;
}

void RaDesDestroy(struct RaDesCtx *ctx)
{
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(struct RaDesCtx));
		free(ctx);
	}
}

void RaDesSetIV(struct RaDesCtx *ctx, const uint8_t iv[8])
{
	RaBlockCipherSetIV(&ctx->blockCipher, iv);
}

void RaDesGetIV(struct RaDesCtx *ctx, /*out*/uint8_t iv[8])
{
	RaBlockCipherGetIV(&ctx->blockCipher, iv);
}

int RaDesEncrypt(struct RaDesCtx *ctx, const uint8_t *input, int length, uint8_t *output)
{
	return RaBlockCipherEncrypt(&ctx->blockCipher, input, length, output);
}

int RaDesEncryptFinal(struct RaDesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType)
{
	return RaBlockCipherEncryptFinal(&ctx->blockCipher, input, length, output, paddingType);
}

int RaDesDecrypt(struct RaDesCtx *ctx, const uint8_t *input, int length, uint8_t *output)
{
	return RaBlockCipherDecrypt(&ctx->blockCipher, input, length, output);
}

int RaDesDecryptFinal(struct RaDesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType)
{
	return RaBlockCipherDecryptFinal(&ctx->blockCipher, input, length, output, paddingType);
}


