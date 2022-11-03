/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>
#include <string.h>
#include <stdlib.h>
#include "block_cipher.h"

// The lookup tables are generated by the following source code
/*
#include <stdio.h>
#include <stdint.h>

#define ROTL8(x,n)		(uint8_t)(((x)>>(8-n))|((x)<<(n)))

static const uint8_t CC[8] = {
	0b11001011,
	0b10111010,
	0b10000001,
	0b00110100,
	0b10111001,
	0b11101011,
	0b10111100,
	0b01111010
};

static uint8_t SS1[256];
static uint8_t SS2[256];
static uint8_t RS1[256];
static uint8_t RS2[256];

static int8_t permute8(uint8_t x, const uint8_t *a)
{
	int i;
	uint32_t ret = 0;
	uint32_t t;

	for (i = 0; i < 8; i++)
	{
		t = x & a[i];
		t ^= t >> 4;
		t ^= t >> 2;
		t ^= t >> 1;
		ret <<= 1;
		ret |= t & 1;
	}
	return (uint8_t)ret;
}

static void printData8(uint8_t *data, int count)
{
	int i;
	printf("\t");
	for (i = 0; i < count; i++)
	{
		if (i == count - 1) {
			printf("V(%02x)\n", data[i]);
		}
		else if ((i % 16) == 15) {
			printf("V(%02x),\n\t", data[i]);
		}
		else {
			printf("V(%02x),", data[i]);
		}
	}
}

uint32_t mul(uint32_t m, uint32_t n)
{
	uint32_t p;
	int i;
	n &= 0xff;
	// multiply
	p = 0;
	for (i = 0; i < 8; i++)
	{
		p <<= 1;
		if (p & 0x100)
			p ^= 0x11b;
		if (m & 0x80)
			p ^= n;
		m <<= 1;
	}
	return p;
}

int main()
{
	uint32_t t;
	uint32_t p, q, r;

	p = 1;
	q = 1;
	do {
		// multiply p by 3
		p = (uint8_t)(p ^ (p << 1) ^ (((int8_t)p >> 7) & 0x1b));
		// divide q by 3 (equals multiplication by 0xf6)
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q = (uint8_t)(q ^ (((int8_t)q>>7) & 0x09));
		q &= 0xff;

		t = mul(q, q);		// (x**-2)
		t = mul(t, t);		// (x**-4)
		t = mul(t, t);		// (x**-8) = (x**247)

		r = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4) ^ 0x63;
		SS1[p] = r;
		RS1[r] = p;
		r = (uint8_t)(permute8((uint8_t)t, CC) ^ 0xe2);
		SS2[p] = r;
		RS2[r] = p;
	} while (p != 1);

	SS1[0] = 0x63;
	RS1[0x63] = 0;
	SS2[0] = 0xe2;
	RS2[0xe2] = 0;

	printf("#define V(v)	0x##00##v##v##v\n");
	printf("static const uint32_t ariaSS1[256] = {\n");
	printData8(SS1, 256);
	printf("};\n");
	printf("#undef V\n");
	printf("#define V(v)	0x##v##00##v##v\n");
	printf("static const uint32_t ariaSS2[256] = {\n");
	printData8(SS2, 256);
	printf("};\n");
	printf("#undef V\n");
	printf("#define V(v)	0x##v##v##00##v\n");
	printf("static const uint32_t ariaRS1[256] = {\n");
	printData8(RS1, 256);
	printf("};\n");
	printf("#undef V\n");
	printf("#define V(v)	0x##v##v##v##00\n");
	printf("static const uint32_t ariaRS2[256] = {\n");
	printData8(RS2, 256);
	printf("};\n");
	printf("#undef V\n");

	return 0;
}
*/
#define V(v)	0x##00##v##v##v
static const uint32_t ariaSS1[256] = {
	V(63),V(7c),V(77),V(7b),V(f2),V(6b),V(6f),V(c5),V(30),V(01),V(67),V(2b),V(fe),V(d7),V(ab),V(76),
	V(ca),V(82),V(c9),V(7d),V(fa),V(59),V(47),V(f0),V(ad),V(d4),V(a2),V(af),V(9c),V(a4),V(72),V(c0),
	V(b7),V(fd),V(93),V(26),V(36),V(3f),V(f7),V(cc),V(34),V(a5),V(e5),V(f1),V(71),V(d8),V(31),V(15),
	V(04),V(c7),V(23),V(c3),V(18),V(96),V(05),V(9a),V(07),V(12),V(80),V(e2),V(eb),V(27),V(b2),V(75),
	V(09),V(83),V(2c),V(1a),V(1b),V(6e),V(5a),V(a0),V(52),V(3b),V(d6),V(b3),V(29),V(e3),V(2f),V(84),
	V(53),V(d1),V(00),V(ed),V(20),V(fc),V(b1),V(5b),V(6a),V(cb),V(be),V(39),V(4a),V(4c),V(58),V(cf),
	V(d0),V(ef),V(aa),V(fb),V(43),V(4d),V(33),V(85),V(45),V(f9),V(02),V(7f),V(50),V(3c),V(9f),V(a8),
	V(51),V(a3),V(40),V(8f),V(92),V(9d),V(38),V(f5),V(bc),V(b6),V(da),V(21),V(10),V(ff),V(f3),V(d2),
	V(cd),V(0c),V(13),V(ec),V(5f),V(97),V(44),V(17),V(c4),V(a7),V(7e),V(3d),V(64),V(5d),V(19),V(73),
	V(60),V(81),V(4f),V(dc),V(22),V(2a),V(90),V(88),V(46),V(ee),V(b8),V(14),V(de),V(5e),V(0b),V(db),
	V(e0),V(32),V(3a),V(0a),V(49),V(06),V(24),V(5c),V(c2),V(d3),V(ac),V(62),V(91),V(95),V(e4),V(79),
	V(e7),V(c8),V(37),V(6d),V(8d),V(d5),V(4e),V(a9),V(6c),V(56),V(f4),V(ea),V(65),V(7a),V(ae),V(08),
	V(ba),V(78),V(25),V(2e),V(1c),V(a6),V(b4),V(c6),V(e8),V(dd),V(74),V(1f),V(4b),V(bd),V(8b),V(8a),
	V(70),V(3e),V(b5),V(66),V(48),V(03),V(f6),V(0e),V(61),V(35),V(57),V(b9),V(86),V(c1),V(1d),V(9e),
	V(e1),V(f8),V(98),V(11),V(69),V(d9),V(8e),V(94),V(9b),V(1e),V(87),V(e9),V(ce),V(55),V(28),V(df),
	V(8c),V(a1),V(89),V(0d),V(bf),V(e6),V(42),V(68),V(41),V(99),V(2d),V(0f),V(b0),V(54),V(bb),V(16)
};
#undef V
#define V(v)	0x##v##00##v##v
static const uint32_t ariaSS2[256] = {
	V(e2),V(4e),V(54),V(fc),V(94),V(c2),V(4a),V(cc),V(62),V(0d),V(6a),V(46),V(3c),V(4d),V(8b),V(d1),
	V(5e),V(fa),V(64),V(cb),V(b4),V(97),V(be),V(2b),V(bc),V(77),V(2e),V(03),V(d3),V(19),V(59),V(c1),
	V(1d),V(06),V(41),V(6b),V(55),V(f0),V(99),V(69),V(ea),V(9c),V(18),V(ae),V(63),V(df),V(e7),V(bb),
	V(00),V(73),V(66),V(fb),V(96),V(4c),V(85),V(e4),V(3a),V(09),V(45),V(aa),V(0f),V(ee),V(10),V(eb),
	V(2d),V(7f),V(f4),V(29),V(ac),V(cf),V(ad),V(91),V(8d),V(78),V(c8),V(95),V(f9),V(2f),V(ce),V(cd),
	V(08),V(7a),V(88),V(38),V(5c),V(83),V(2a),V(28),V(47),V(db),V(b8),V(c7),V(93),V(a4),V(12),V(53),
	V(ff),V(87),V(0e),V(31),V(36),V(21),V(58),V(48),V(01),V(8e),V(37),V(74),V(32),V(ca),V(e9),V(b1),
	V(b7),V(ab),V(0c),V(d7),V(c4),V(56),V(42),V(26),V(07),V(98),V(60),V(d9),V(b6),V(b9),V(11),V(40),
	V(ec),V(20),V(8c),V(bd),V(a0),V(c9),V(84),V(04),V(49),V(23),V(f1),V(4f),V(50),V(1f),V(13),V(dc),
	V(d8),V(c0),V(9e),V(57),V(e3),V(c3),V(7b),V(65),V(3b),V(02),V(8f),V(3e),V(e8),V(25),V(92),V(e5),
	V(15),V(dd),V(fd),V(17),V(a9),V(bf),V(d4),V(9a),V(7e),V(c5),V(39),V(67),V(fe),V(76),V(9d),V(43),
	V(a7),V(e1),V(d0),V(f5),V(68),V(f2),V(1b),V(34),V(70),V(05),V(a3),V(8a),V(d5),V(79),V(86),V(a8),
	V(30),V(c6),V(51),V(4b),V(1e),V(a6),V(27),V(f6),V(35),V(d2),V(6e),V(24),V(16),V(82),V(5f),V(da),
	V(e6),V(75),V(a2),V(ef),V(2c),V(b2),V(1c),V(9f),V(5d),V(6f),V(80),V(0a),V(72),V(44),V(9b),V(6c),
	V(90),V(0b),V(5b),V(33),V(7d),V(5a),V(52),V(f3),V(61),V(a1),V(f7),V(b0),V(d6),V(3f),V(7c),V(6d),
	V(ed),V(14),V(e0),V(a5),V(3d),V(22),V(b3),V(f8),V(89),V(de),V(71),V(1a),V(af),V(ba),V(b5),V(81)
};
#undef V
#define V(v)	0x##v##v##00##v
static const uint32_t ariaRS1[256] = {
	V(52),V(09),V(6a),V(d5),V(30),V(36),V(a5),V(38),V(bf),V(40),V(a3),V(9e),V(81),V(f3),V(d7),V(fb),
	V(7c),V(e3),V(39),V(82),V(9b),V(2f),V(ff),V(87),V(34),V(8e),V(43),V(44),V(c4),V(de),V(e9),V(cb),
	V(54),V(7b),V(94),V(32),V(a6),V(c2),V(23),V(3d),V(ee),V(4c),V(95),V(0b),V(42),V(fa),V(c3),V(4e),
	V(08),V(2e),V(a1),V(66),V(28),V(d9),V(24),V(b2),V(76),V(5b),V(a2),V(49),V(6d),V(8b),V(d1),V(25),
	V(72),V(f8),V(f6),V(64),V(86),V(68),V(98),V(16),V(d4),V(a4),V(5c),V(cc),V(5d),V(65),V(b6),V(92),
	V(6c),V(70),V(48),V(50),V(fd),V(ed),V(b9),V(da),V(5e),V(15),V(46),V(57),V(a7),V(8d),V(9d),V(84),
	V(90),V(d8),V(ab),V(00),V(8c),V(bc),V(d3),V(0a),V(f7),V(e4),V(58),V(05),V(b8),V(b3),V(45),V(06),
	V(d0),V(2c),V(1e),V(8f),V(ca),V(3f),V(0f),V(02),V(c1),V(af),V(bd),V(03),V(01),V(13),V(8a),V(6b),
	V(3a),V(91),V(11),V(41),V(4f),V(67),V(dc),V(ea),V(97),V(f2),V(cf),V(ce),V(f0),V(b4),V(e6),V(73),
	V(96),V(ac),V(74),V(22),V(e7),V(ad),V(35),V(85),V(e2),V(f9),V(37),V(e8),V(1c),V(75),V(df),V(6e),
	V(47),V(f1),V(1a),V(71),V(1d),V(29),V(c5),V(89),V(6f),V(b7),V(62),V(0e),V(aa),V(18),V(be),V(1b),
	V(fc),V(56),V(3e),V(4b),V(c6),V(d2),V(79),V(20),V(9a),V(db),V(c0),V(fe),V(78),V(cd),V(5a),V(f4),
	V(1f),V(dd),V(a8),V(33),V(88),V(07),V(c7),V(31),V(b1),V(12),V(10),V(59),V(27),V(80),V(ec),V(5f),
	V(60),V(51),V(7f),V(a9),V(19),V(b5),V(4a),V(0d),V(2d),V(e5),V(7a),V(9f),V(93),V(c9),V(9c),V(ef),
	V(a0),V(e0),V(3b),V(4d),V(ae),V(2a),V(f5),V(b0),V(c8),V(eb),V(bb),V(3c),V(83),V(53),V(99),V(61),
	V(17),V(2b),V(04),V(7e),V(ba),V(77),V(d6),V(26),V(e1),V(69),V(14),V(63),V(55),V(21),V(0c),V(7d)
};
#undef V
#define V(v)	0x##v##v##v##00
static const uint32_t ariaRS2[256] = {
	V(30),V(68),V(99),V(1b),V(87),V(b9),V(21),V(78),V(50),V(39),V(db),V(e1),V(72),V(09),V(62),V(3c),
	V(3e),V(7e),V(5e),V(8e),V(f1),V(a0),V(cc),V(a3),V(2a),V(1d),V(fb),V(b6),V(d6),V(20),V(c4),V(8d),
	V(81),V(65),V(f5),V(89),V(cb),V(9d),V(77),V(c6),V(57),V(43),V(56),V(17),V(d4),V(40),V(1a),V(4d),
	V(c0),V(63),V(6c),V(e3),V(b7),V(c8),V(64),V(6a),V(53),V(aa),V(38),V(98),V(0c),V(f4),V(9b),V(ed),
	V(7f),V(22),V(76),V(af),V(dd),V(3a),V(0b),V(58),V(67),V(88),V(06),V(c3),V(35),V(0d),V(01),V(8b),
	V(8c),V(c2),V(e6),V(5f),V(02),V(24),V(75),V(93),V(66),V(1e),V(e5),V(e2),V(54),V(d8),V(10),V(ce),
	V(7a),V(e8),V(08),V(2c),V(12),V(97),V(32),V(ab),V(b4),V(27),V(0a),V(23),V(df),V(ef),V(ca),V(d9),
	V(b8),V(fa),V(dc),V(31),V(6b),V(d1),V(ad),V(19),V(49),V(bd),V(51),V(96),V(ee),V(e4),V(a8),V(41),
	V(da),V(ff),V(cd),V(55),V(86),V(36),V(be),V(61),V(52),V(f8),V(bb),V(0e),V(82),V(48),V(69),V(9a),
	V(e0),V(47),V(9e),V(5c),V(04),V(4b),V(34),V(15),V(79),V(26),V(a7),V(de),V(29),V(ae),V(92),V(d7),
	V(84),V(e9),V(d2),V(ba),V(5d),V(f3),V(c5),V(b0),V(bf),V(a4),V(3b),V(71),V(44),V(46),V(2b),V(fc),
	V(eb),V(6f),V(d5),V(f6),V(14),V(fe),V(7c),V(70),V(5a),V(7d),V(fd),V(2f),V(18),V(83),V(16),V(a5),
	V(91),V(1f),V(05),V(95),V(74),V(a9),V(c1),V(5b),V(4a),V(85),V(6d),V(13),V(07),V(4f),V(4e),V(45),
	V(b2),V(0f),V(c9),V(1c),V(a6),V(bc),V(ec),V(73),V(90),V(7b),V(cf),V(59),V(8f),V(a1),V(f9),V(2d),
	V(f2),V(b1),V(00),V(94),V(37),V(9f),V(d0),V(2e),V(9c),V(6e),V(28),V(3f),V(80),V(f0),V(3d),V(d3),
	V(25),V(8a),V(b5),V(e7),V(42),V(b3),V(c7),V(ea),V(f7),V(4c),V(11),V(33),V(03),V(a2),V(ac),V(60)
};
#undef V

const uint32_t ariaCK[3][4] = {
  {0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0},
  {0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0},
  {0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e}
};

#define GET_UINT32_BE(b)		(uint32_t)(((b)[0] << 24)|((b)[1] << 16)|((b)[2] << 8)|(b)[3])
#define PUT_UINT32_BE(b, v)		{ (b)[0] = (uint8_t)((v)>>24); (b)[1] = (uint8_t)((v)>>16); (b)[2] = (uint8_t)((v)>>8); (b)[3] = (uint8_t)(v); }

#define SS1		ariaSS1
#define SS2		ariaSS2
#define RS1		ariaRS1
#define RS2		ariaRS2
#define CK		ariaCK

#define ARIA_MSO(A,B,C,D)	\
	A = SS1[(uint8_t)(A>>24)]^SS2[(uint8_t)(A>>16)]^RS1[(uint8_t)(A>>8)]^RS2[(uint8_t)A];	\
	B = SS1[(uint8_t)(B>>24)]^SS2[(uint8_t)(B>>16)]^RS1[(uint8_t)(B>>8)]^RS2[(uint8_t)B];	\
	C = SS1[(uint8_t)(C>>24)]^SS2[(uint8_t)(C>>16)]^RS1[(uint8_t)(C>>8)]^RS2[(uint8_t)C];	\
	D = SS1[(uint8_t)(D>>24)]^SS2[(uint8_t)(D>>16)]^RS1[(uint8_t)(D>>8)]^RS2[(uint8_t)D]

#define ARIA_MSE(A,B,C,D)	\
	A = RS1[(uint8_t)(A>>24)]^RS2[(uint8_t)(A>>16)]^SS1[(uint8_t)(A>>8)]^SS2[(uint8_t)A];	\
	B = RS1[(uint8_t)(B>>24)]^RS2[(uint8_t)(B>>16)]^SS1[(uint8_t)(B>>8)]^SS2[(uint8_t)B];	\
	C = RS1[(uint8_t)(C>>24)]^RS2[(uint8_t)(C>>16)]^SS1[(uint8_t)(C>>8)]^SS2[(uint8_t)C];	\
	D = RS1[(uint8_t)(D>>24)]^RS2[(uint8_t)(D>>16)]^SS1[(uint8_t)(D>>8)]^SS2[(uint8_t)D]

#define ARIA_XOR(A,B,C,D,key)	\
	A ^= key[0];	\
	B ^= key[1];	\
	C ^= key[2];	\
	D ^= key[3]

// A' = A ^ B ^ C
// B' = A     ^ C ^ D
// C' = A ^ B     ^ D
// D' =     B ^ C ^ D
#define ARIA_M1(A,B,C,D)	\
	B ^= C;		\
	C ^= D;		\
	A ^= B;		\
	D ^= B;		\
	C ^= A;		\
	B ^= C

// P
// | I  0  0  0	 |
// | 0  P1 0  0	 |
// | 0  0  P2 0	 |
// | 0  0  0  P3 |
#define ARIA_PO(A,B,C,D)	\
	/*A = A;*/	\
	B = ((B << 8) & 0xff00ff00) | ((B >> 8) & 0x00ff00ff);	\
	C = (C << 16) | (C >> 16);	\
	D = (D << 16) | (D >> 16);	\
	D = ((D << 8) & 0xff00ff00) | ((D >> 8) & 0x00ff00ff)
// Words in even rounds are swapped in 16bit units after DO_MSL2 is done. First, swap it in 16bit units and apply P
#define ARIA_PE(A,B,C,D)	\
	A = (A << 16) | (A >> 16);	\
	B = (B << 16) | (B >> 16);	\
	B = ((B << 8) & 0xff00ff00) | ((B >> 8) & 0x00ff00ff);	\
	/*C = C;*/	\
	D = ((D << 8) & 0xff00ff00) | ((D >> 8) & 0x00ff00ff)

#define ARIA_FO(A,B,C,D,key)	\
	ARIA_XOR(A,B,C,D,key);		\
	ARIA_MSO(A,B,C,D);			\
	ARIA_M1(A,B,C,D);			\
	ARIA_PO(A,B,C,D);			\
	ARIA_M1(A,B,C,D)

#define ARIA_FE(A,B,C,D,key)	\
	ARIA_XOR(A,B,C,D,key);		\
	ARIA_MSE(A,B,C,D);			\
	ARIA_M1(A,B,C,D);			\
	ARIA_PE(A,B,C,D);			\
	ARIA_M1(A,B,C,D)

#define ARIA_SF(X)				\
	X = (RS1[(uint8_t)(X>>24)] & 0xff000000) |	\
		(RS2[(uint8_t)(X>>16)] & 0x00ff0000) |	\
		(SS1[(uint8_t)(X>> 8)] & 0x0000ff00) |	\
		(SS2[(uint8_t)X      ] & 0x000000ff)

#define ARIA_FF(A,B,C,D,key,key2)	\
	ARIA_XOR(A,B,C,D,key);		\
	ARIA_SF(A);	\
	ARIA_SF(B);	\
	ARIA_SF(C);	\
	ARIA_SF(D);	\
	ARIA_XOR(A,B,C,D,key2)

#define ARIA_GSRK(key,A,B,n)	\
	q = 4 - (n / 32);	\
	r = n % 32;	\
	key[0] = A[0] ^ (B[(q + 0) % 4] >> r) ^ (B[(q + 3) % 4] << (32 - r));	\
	key[1] = A[1] ^ (B[(q + 1) % 4] >> r) ^ (B[(q + 0) % 4] << (32 - r));	\
	key[2] = A[2] ^ (B[(q + 2) % 4] >> r) ^ (B[(q + 1) % 4] << (32 - r));	\
	key[3] = A[3] ^ (B[(q + 3) % 4] >> r) ^ (B[(q + 2) % 4] << (32 - r))
// T
// | 0  1  1  1	 |
// | 1  0  1  1	 |
// | 1  1  0  1	 |
// | 1  1  1  0  |
// M
// | T  0  0  0	 |
// | 0  T  0  0	 |
// | 0  0  T  0	 |
// | 0  0  0  T  |
#define ARIA_MW(A,B,C,D)	\
	A = (A<<8) ^ (A>>24) ^ (A<<16) ^ (A>>16) ^ (A>>8) ^ (A<<24);	\
	B = (B<<8) ^ (B>>24) ^ (B<<16) ^ (B>>16) ^ (B>>8) ^ (B<<24);	\
	C = (C<<8) ^ (C>>24) ^ (C<<16) ^ (C>>16) ^ (C>>8) ^ (C<<24);	\
	D = (D<<8) ^ (D>>24) ^ (D<<16) ^ (D>>16) ^ (D>>8) ^ (D<<24)

static void RaAriaEncryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output);
static void RaAriaDecryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output);

int RaAriaCreate(const uint8_t *key, enum RaAriaKeyType keyType, enum RaBlockCipherMode opMode, struct RaAriaCtx **ctxp)
{
	struct RaAriaCtx *ctx;

	ctx = malloc(sizeof(struct RaAriaCtx));
	if (ctx == NULL)
		return RA_ERR_OUT_OF_MEMORY;

	RaAriaInit(ctx, key, keyType, opMode);

	*ctxp = ctx;

	return RA_ERR_SUCCESS;
}

void RaAriaDestroy(struct RaAriaCtx *ctx)
{
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(struct RaAriaCtx));
		free(ctx);
	}
}

void RaAriaInit(struct RaAriaCtx *ctx, const uint8_t *key, enum RaAriaKeyType keyType, enum RaBlockCipherMode opMode)
{
	uint32_t t0, t1, t2, t3;
	uint32_t w0[4], w1[4], w2[4], w3[4];
	int q, r;

	RaBlockCipherInit(&ctx->blockCipher, RaAriaEncryptBlock, RaAriaDecryptBlock, opMode, RA_BLOCK_LEN_ARIA, ctx->iv, ctx->buffer);
	
	w0[0] = GET_UINT32_BE(key);
	w0[1] = GET_UINT32_BE(key + 4);
	w0[2] = GET_UINT32_BE(key + 8);
	w0[3] = GET_UINT32_BE(key + 12);

	switch (keyType)
	{
	case RA_ARIA_128: default:
		ctx->nr = 12;
		q = 0;
		w1[0] = 0;
		w1[1] = 0;
		w1[2] = 0;
		w1[3] = 0;
		break;
	case RA_ARIA_192:
		ctx->nr = 14;
		q = 1;
		w1[0] = GET_UINT32_BE(key + 16);
		w1[1] = GET_UINT32_BE(key + 20);
		w1[2] = 0;
		w1[3] = 0;
		break;
	case RA_ARIA_256:
		ctx->nr = 16;
		q = 2;
		w1[0] = GET_UINT32_BE(key + 16);
		w1[1] = GET_UINT32_BE(key + 20);
		w1[2] = GET_UINT32_BE(key + 24);
		w1[3] = GET_UINT32_BE(key + 28);
		break;
	}
	// expand key
	t0 = w0[0]; t1 = w0[1]; t2 = w0[2]; t3 = w0[3];
	ARIA_FO(t0, t1, t2, t3, CK[q]);

	w1[0] ^= t0; w1[1] ^= t1; w1[2] ^= t2; w1[3] ^= t3;

	t0 = w1[0]; t1 = w1[1]; t2 = w1[2]; t3 = w1[3];
	q = (q + 1) % 3;
	ARIA_FE(t0, t1, t2, t3, CK[q]);
	w2[0] = t0 ^= w0[0];
	w2[1] = t1 ^= w0[1];
	w2[2] = t2 ^= w0[2];
	w2[3] = t3 ^= w0[3];

	q = (q + 1) % 3;
	ARIA_FO(t0, t1, t2, t3, CK[q]);
	w3[0] = t0 ^ w1[0];
	w3[1] = t1 ^ w1[1];
	w3[2] = t2 ^ w1[2];
	w3[3] = t3 ^ w1[3];

	// setup round key
	ARIA_GSRK(ctx->round_key[0], w0, w1, 19);
	ARIA_GSRK(ctx->round_key[1], w1, w2, 19);
	ARIA_GSRK(ctx->round_key[2], w2, w3, 19);
	ARIA_GSRK(ctx->round_key[3], w3, w0, 19);
	ARIA_GSRK(ctx->round_key[4], w0, w1, 31);
	ARIA_GSRK(ctx->round_key[5], w1, w2, 31);
	ARIA_GSRK(ctx->round_key[6], w2, w3, 31);
	ARIA_GSRK(ctx->round_key[7], w3, w0, 31);
	ARIA_GSRK(ctx->round_key[8], w0, w1, 67);
	ARIA_GSRK(ctx->round_key[9], w1, w2, 67);
	ARIA_GSRK(ctx->round_key[10], w2, w3, 67);
	ARIA_GSRK(ctx->round_key[11], w3, w0, 67);
	ARIA_GSRK(ctx->round_key[12], w0, w1, 97);
	switch (keyType)
	{
	case RA_ARIA_256:
		ARIA_GSRK(ctx->round_key[15], w3, w0, 97);
		ARIA_GSRK(ctx->round_key[16], w0, w1, 109);
	case RA_ARIA_192:
		ARIA_GSRK(ctx->round_key[13], w1, w2, 97);
		ARIA_GSRK(ctx->round_key[14], w2, w3, 97);
		break;
	default:
		break;
	}
	// setup reverse round key
	ctx->rev_key[0][0] = ctx->round_key[ctx->nr][0];
	ctx->rev_key[0][1] = ctx->round_key[ctx->nr][1];
	ctx->rev_key[0][2] = ctx->round_key[ctx->nr][2];
	ctx->rev_key[0][3] = ctx->round_key[ctx->nr][3];
	ctx->rev_key[ctx->nr][0] = ctx->round_key[0][0];
	ctx->rev_key[ctx->nr][1] = ctx->round_key[0][1];
	ctx->rev_key[ctx->nr][2] = ctx->round_key[0][2];
	ctx->rev_key[ctx->nr][3] = ctx->round_key[0][3];
	r = ctx->nr - 1;
	for (q = 1; q <= ctx->nr - 1; q++) {
		t0 = ctx->round_key[r][0];
		t1 = ctx->round_key[r][1];
		t2 = ctx->round_key[r][2];
		t3 = ctx->round_key[r][3];
		ARIA_MW(t0, t1, t2, t3);
		ARIA_M1(t0, t1, t2, t3);
		ARIA_PO(t0, t1, t2, t3);
		ARIA_M1(t0, t1, t2, t3);
		ctx->rev_key[q][0] = t0;
		ctx->rev_key[q][1] = t1;
		ctx->rev_key[q][2] = t2;
		ctx->rev_key[q][3] = t3;
		r--;
	}
}

static void RaAriaEncryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output)
{
	uint32_t t0, t1, t2, t3;
	int i;
	struct RaAriaCtx *ctx;
	ctx = CHILD_OF(blockCipher, struct RaAriaCtx, blockCipher);

	t0 = GET_UINT32_BE(input);
	t1 = GET_UINT32_BE(input + 4);
	t2 = GET_UINT32_BE(input + 8);
	t3 = GET_UINT32_BE(input + 12);

	for (i = 0; i <= ctx->nr - 4; i += 2) {
		ARIA_FO(t0, t1, t2, t3, ctx->round_key[i]);
		ARIA_FE(t0, t1, t2, t3, ctx->round_key[i + 1]);
	}
	ARIA_FO(t0, t1, t2, t3, ctx->round_key[ctx->nr - 2]);
	ARIA_FF(t0, t1, t2, t3, ctx->round_key[ctx->nr - 1], ctx->round_key[ctx->nr]);
	
	PUT_UINT32_BE(output     , t0);
	PUT_UINT32_BE(output + 4 , t1);
	PUT_UINT32_BE(output + 8 , t2);
	PUT_UINT32_BE(output + 12, t3);
}

static void RaAriaDecryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output)
{
	uint32_t t0, t1, t2, t3;
	int i;
	struct RaAriaCtx *ctx;
	ctx = CHILD_OF(blockCipher, struct RaAriaCtx, blockCipher);

	t0 = GET_UINT32_BE(input);
	t1 = GET_UINT32_BE(input + 4);
	t2 = GET_UINT32_BE(input + 8);
	t3 = GET_UINT32_BE(input + 12);

	for (i = 0; i <= ctx->nr - 4; i += 2) {
		ARIA_FO(t0, t1, t2, t3, ctx->rev_key[i]);
		ARIA_FE(t0, t1, t2, t3, ctx->rev_key[i + 1]);
	}
	ARIA_FO(t0, t1, t2, t3, ctx->rev_key[ctx->nr - 2]);
	ARIA_FF(t0, t1, t2, t3, ctx->rev_key[ctx->nr - 1], ctx->rev_key[ctx->nr]);

	PUT_UINT32_BE(output     , t0);
	PUT_UINT32_BE(output + 4 , t1);
	PUT_UINT32_BE(output + 8 , t2);
	PUT_UINT32_BE(output + 12, t3);
}

void RaAriaSetIV(struct RaAriaCtx *ctx, const uint8_t iv[16])
{
	RaBlockCipherSetIV(&ctx->blockCipher, iv);
}

void RaAriaGetIV(struct RaAriaCtx *ctx, /*out*/uint8_t iv[16])
{
	RaBlockCipherGetIV(&ctx->blockCipher, iv);
}

int RaAriaEncrypt(struct RaAriaCtx *ctx, const uint8_t *input, int length, uint8_t *output)
{
	return RaBlockCipherEncrypt(&ctx->blockCipher, input, length, output);
}

int RaAriaEncryptFinal(struct RaAriaCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType)
{
	return RaBlockCipherEncryptFinal(&ctx->blockCipher, input, length, output, paddingType);
}

int RaAriaDecrypt(struct RaAriaCtx *ctx, const uint8_t *input, int length, uint8_t *output)
{
	return RaBlockCipherDecrypt(&ctx->blockCipher, input, length, output);
}

int RaAriaDecryptFinal(struct RaAriaCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType)
{
	return RaBlockCipherDecryptFinal(&ctx->blockCipher, input, length, output, paddingType);
}


#undef SS1
#undef SS2
#undef RS1
#undef RS2
#undef CK
#undef ARIA_MSO
#undef ARIA_MSE
#undef ARIA_XOR
#undef ARIA_M1
#undef ARIA_PO
#undef ARIA_PE
#undef ARIA_FO
#undef ARIA_FE
#undef ARIA_SF
#undef ARIA_FF
#undef ARIA_GSRK
#undef ARIA_MW