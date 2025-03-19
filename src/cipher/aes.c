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

#define X1(v)		(s[v])
#define X2(v)		(xtime2[s[v]])
#define X3(v)		(xtime2[s[v]] ^ s[v])

#define X9(v)		(xtime9[rev_s[v]])
#define X11(v)		(xtime9[rev_s[v]] ^ xtime2[rev_s[v]])
#define X13(v)		(xtime9[rev_s[v]] ^ xtime4[rev_s[v]])
#define X14(v)		(xtime14[rev_s[v]])

int main()
{
	int p;
	int q;
	int r;
	int i;
	
	uint8_t xtime2[256];
	uint8_t xtime4[256];
	uint8_t xtime8[256];
	uint8_t xtime9[256];
	uint8_t xtime14[256];
	uint8_t s[256];
	uint8_t rev_s[256];
	
	printf("static const uint32_t rcon[10] = {\n\t0x01");
	r = 1;
	for (i = 1; i < 10; i++) {
		r = (uint8_t)((r << 1) ^ (((int8_t)r >> 7) & 0x1b));
		printf( ", 0x%02x", r );
	}
	printf("\n};\n\n");

	// calculate Rijndael's S-box
	// ref: https://en.wikipedia.org/wiki/Rijndael_S-box
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

		r = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4) ^ 0x63;
		s[p] = r;
		rev_s[r] = p;
	} while(p != 1);
	// 0 is a special case since it has no inverse
	s[0] = 0x63;
	rev_s[0x63] = 0;
	
	printf("// Rijndael's S-box\n");
	printf("static const uint8_t s[256] = {\n\t0x%02x", s[0]);
	for (i = 1; i < 256; i++) {
		if ((i % 16) == 0)
			printf(",\n\t0x%02x", s[i]);
		else
			printf(", 0x%02x", s[i]);
	}
	printf("\n};\n\n");
	
	printf("static const uint8_t rev_s[256] = {\n\t0x%02x", rev_s[0]);
	for (i = 1; i < 256; i++) {
		if ((i % 16) == 0)
			printf(",\n\t0x%02x", rev_s[i]);
		else
			printf(", 0x%02x", rev_s[i]);
	}
	printf("\n};\n\n");
	
	for (i = 0; i < 256; i++) {
		xtime2[i] = (uint8_t)( ( i << 1 ) ^ ( ( (int8_t)i >> 7 ) & 0x1b ) );
	}
	for (i = 0; i < 256; i++) {
		xtime4[i] = xtime2[xtime2[i]];
	}
	for (i = 0; i < 256; i++) {
		xtime8[i] = xtime4[xtime2[i]];
		xtime9[i] = xtime8[i] ^ i;
		xtime14[i] = xtime8[i] ^ xtime4[i] ^ xtime2[i];
	}

	printf( "#define AES_LOOKUP\t" );
	for(i = 0; i < 256; i++) {
		if (i != 0)
			printf(",");
		if ( (i % 8) == 0 )
			printf("\\\n\t");
		printf("V(%02x,%02x,%02x,%02x)",
			X2(i), X1(i), X1(i), X3(i) );
	}
	printf("\n");
	printf( "#define AES_REV_LOOKUP\t" );
	for(i = 0; i < 256; i++) {
		if (i != 0)
			printf(",");
		if ( (i % 8) == 0 )
			printf("\\\n\t");
		printf("V(%02x,%02x,%02x,%02x)",
			X14(i), X9(i), X13(i), X11(i) );
	}
	printf("\n");

	return 0;
}
*/

static const uint8_t rcon[10] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Rijndael's S-box
static const uint8_t s[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rev_s[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

#define AES_LOOKUP	\
	V(c6,63,63,a5),V(f8,7c,7c,84),V(ee,77,77,99),V(f6,7b,7b,8d),V(ff,f2,f2,0d),V(d6,6b,6b,bd),V(de,6f,6f,b1),V(91,c5,c5,54),\
	V(60,30,30,50),V(02,01,01,03),V(ce,67,67,a9),V(56,2b,2b,7d),V(e7,fe,fe,19),V(b5,d7,d7,62),V(4d,ab,ab,e6),V(ec,76,76,9a),\
	V(8f,ca,ca,45),V(1f,82,82,9d),V(89,c9,c9,40),V(fa,7d,7d,87),V(ef,fa,fa,15),V(b2,59,59,eb),V(8e,47,47,c9),V(fb,f0,f0,0b),\
	V(41,ad,ad,ec),V(b3,d4,d4,67),V(5f,a2,a2,fd),V(45,af,af,ea),V(23,9c,9c,bf),V(53,a4,a4,f7),V(e4,72,72,96),V(9b,c0,c0,5b),\
	V(75,b7,b7,c2),V(e1,fd,fd,1c),V(3d,93,93,ae),V(4c,26,26,6a),V(6c,36,36,5a),V(7e,3f,3f,41),V(f5,f7,f7,02),V(83,cc,cc,4f),\
	V(68,34,34,5c),V(51,a5,a5,f4),V(d1,e5,e5,34),V(f9,f1,f1,08),V(e2,71,71,93),V(ab,d8,d8,73),V(62,31,31,53),V(2a,15,15,3f),\
	V(08,04,04,0c),V(95,c7,c7,52),V(46,23,23,65),V(9d,c3,c3,5e),V(30,18,18,28),V(37,96,96,a1),V(0a,05,05,0f),V(2f,9a,9a,b5),\
	V(0e,07,07,09),V(24,12,12,36),V(1b,80,80,9b),V(df,e2,e2,3d),V(cd,eb,eb,26),V(4e,27,27,69),V(7f,b2,b2,cd),V(ea,75,75,9f),\
	V(12,09,09,1b),V(1d,83,83,9e),V(58,2c,2c,74),V(34,1a,1a,2e),V(36,1b,1b,2d),V(dc,6e,6e,b2),V(b4,5a,5a,ee),V(5b,a0,a0,fb),\
	V(a4,52,52,f6),V(76,3b,3b,4d),V(b7,d6,d6,61),V(7d,b3,b3,ce),V(52,29,29,7b),V(dd,e3,e3,3e),V(5e,2f,2f,71),V(13,84,84,97),\
	V(a6,53,53,f5),V(b9,d1,d1,68),V(00,00,00,00),V(c1,ed,ed,2c),V(40,20,20,60),V(e3,fc,fc,1f),V(79,b1,b1,c8),V(b6,5b,5b,ed),\
	V(d4,6a,6a,be),V(8d,cb,cb,46),V(67,be,be,d9),V(72,39,39,4b),V(94,4a,4a,de),V(98,4c,4c,d4),V(b0,58,58,e8),V(85,cf,cf,4a),\
	V(bb,d0,d0,6b),V(c5,ef,ef,2a),V(4f,aa,aa,e5),V(ed,fb,fb,16),V(86,43,43,c5),V(9a,4d,4d,d7),V(66,33,33,55),V(11,85,85,94),\
	V(8a,45,45,cf),V(e9,f9,f9,10),V(04,02,02,06),V(fe,7f,7f,81),V(a0,50,50,f0),V(78,3c,3c,44),V(25,9f,9f,ba),V(4b,a8,a8,e3),\
	V(a2,51,51,f3),V(5d,a3,a3,fe),V(80,40,40,c0),V(05,8f,8f,8a),V(3f,92,92,ad),V(21,9d,9d,bc),V(70,38,38,48),V(f1,f5,f5,04),\
	V(63,bc,bc,df),V(77,b6,b6,c1),V(af,da,da,75),V(42,21,21,63),V(20,10,10,30),V(e5,ff,ff,1a),V(fd,f3,f3,0e),V(bf,d2,d2,6d),\
	V(81,cd,cd,4c),V(18,0c,0c,14),V(26,13,13,35),V(c3,ec,ec,2f),V(be,5f,5f,e1),V(35,97,97,a2),V(88,44,44,cc),V(2e,17,17,39),\
	V(93,c4,c4,57),V(55,a7,a7,f2),V(fc,7e,7e,82),V(7a,3d,3d,47),V(c8,64,64,ac),V(ba,5d,5d,e7),V(32,19,19,2b),V(e6,73,73,95),\
	V(c0,60,60,a0),V(19,81,81,98),V(9e,4f,4f,d1),V(a3,dc,dc,7f),V(44,22,22,66),V(54,2a,2a,7e),V(3b,90,90,ab),V(0b,88,88,83),\
	V(8c,46,46,ca),V(c7,ee,ee,29),V(6b,b8,b8,d3),V(28,14,14,3c),V(a7,de,de,79),V(bc,5e,5e,e2),V(16,0b,0b,1d),V(ad,db,db,76),\
	V(db,e0,e0,3b),V(64,32,32,56),V(74,3a,3a,4e),V(14,0a,0a,1e),V(92,49,49,db),V(0c,06,06,0a),V(48,24,24,6c),V(b8,5c,5c,e4),\
	V(9f,c2,c2,5d),V(bd,d3,d3,6e),V(43,ac,ac,ef),V(c4,62,62,a6),V(39,91,91,a8),V(31,95,95,a4),V(d3,e4,e4,37),V(f2,79,79,8b),\
	V(d5,e7,e7,32),V(8b,c8,c8,43),V(6e,37,37,59),V(da,6d,6d,b7),V(01,8d,8d,8c),V(b1,d5,d5,64),V(9c,4e,4e,d2),V(49,a9,a9,e0),\
	V(d8,6c,6c,b4),V(ac,56,56,fa),V(f3,f4,f4,07),V(cf,ea,ea,25),V(ca,65,65,af),V(f4,7a,7a,8e),V(47,ae,ae,e9),V(10,08,08,18),\
	V(6f,ba,ba,d5),V(f0,78,78,88),V(4a,25,25,6f),V(5c,2e,2e,72),V(38,1c,1c,24),V(57,a6,a6,f1),V(73,b4,b4,c7),V(97,c6,c6,51),\
	V(cb,e8,e8,23),V(a1,dd,dd,7c),V(e8,74,74,9c),V(3e,1f,1f,21),V(96,4b,4b,dd),V(61,bd,bd,dc),V(0d,8b,8b,86),V(0f,8a,8a,85),\
	V(e0,70,70,90),V(7c,3e,3e,42),V(71,b5,b5,c4),V(cc,66,66,aa),V(90,48,48,d8),V(06,03,03,05),V(f7,f6,f6,01),V(1c,0e,0e,12),\
	V(c2,61,61,a3),V(6a,35,35,5f),V(ae,57,57,f9),V(69,b9,b9,d0),V(17,86,86,91),V(99,c1,c1,58),V(3a,1d,1d,27),V(27,9e,9e,b9),\
	V(d9,e1,e1,38),V(eb,f8,f8,13),V(2b,98,98,b3),V(22,11,11,33),V(d2,69,69,bb),V(a9,d9,d9,70),V(07,8e,8e,89),V(33,94,94,a7),\
	V(2d,9b,9b,b6),V(3c,1e,1e,22),V(15,87,87,92),V(c9,e9,e9,20),V(87,ce,ce,49),V(aa,55,55,ff),V(50,28,28,78),V(a5,df,df,7a),\
	V(03,8c,8c,8f),V(59,a1,a1,f8),V(09,89,89,80),V(1a,0d,0d,17),V(65,bf,bf,da),V(d7,e6,e6,31),V(84,42,42,c6),V(d0,68,68,b8),\
	V(82,41,41,c3),V(29,99,99,b0),V(5a,2d,2d,77),V(1e,0f,0f,11),V(7b,b0,b0,cb),V(a8,54,54,fc),V(6d,bb,bb,d6),V(2c,16,16,3a)
#define AES_REV_LOOKUP	\
	V(51,f4,a7,50),V(7e,41,65,53),V(1a,17,a4,c3),V(3a,27,5e,96),V(3b,ab,6b,cb),V(1f,9d,45,f1),V(ac,fa,58,ab),V(4b,e3,03,93),\
	V(20,30,fa,55),V(ad,76,6d,f6),V(88,cc,76,91),V(f5,02,4c,25),V(4f,e5,d7,fc),V(c5,2a,cb,d7),V(26,35,44,80),V(b5,62,a3,8f),\
	V(de,b1,5a,49),V(25,ba,1b,67),V(45,ea,0e,98),V(5d,fe,c0,e1),V(c3,2f,75,02),V(81,4c,f0,12),V(8d,46,97,a3),V(6b,d3,f9,c6),\
	V(03,8f,5f,e7),V(15,92,9c,95),V(bf,6d,7a,eb),V(95,52,59,da),V(d4,be,83,2d),V(58,74,21,d3),V(49,e0,69,29),V(8e,c9,c8,44),\
	V(75,c2,89,6a),V(f4,8e,79,78),V(99,58,3e,6b),V(27,b9,71,dd),V(be,e1,4f,b6),V(f0,88,ad,17),V(c9,20,ac,66),V(7d,ce,3a,b4),\
	V(63,df,4a,18),V(e5,1a,31,82),V(97,51,33,60),V(62,53,7f,45),V(b1,64,77,e0),V(bb,6b,ae,84),V(fe,81,a0,1c),V(f9,08,2b,94),\
	V(70,48,68,58),V(8f,45,fd,19),V(94,de,6c,87),V(52,7b,f8,b7),V(ab,73,d3,23),V(72,4b,02,e2),V(e3,1f,8f,57),V(66,55,ab,2a),\
	V(b2,eb,28,07),V(2f,b5,c2,03),V(86,c5,7b,9a),V(d3,37,08,a5),V(30,28,87,f2),V(23,bf,a5,b2),V(02,03,6a,ba),V(ed,16,82,5c),\
	V(8a,cf,1c,2b),V(a7,79,b4,92),V(f3,07,f2,f0),V(4e,69,e2,a1),V(65,da,f4,cd),V(06,05,be,d5),V(d1,34,62,1f),V(c4,a6,fe,8a),\
	V(34,2e,53,9d),V(a2,f3,55,a0),V(05,8a,e1,32),V(a4,f6,eb,75),V(0b,83,ec,39),V(40,60,ef,aa),V(5e,71,9f,06),V(bd,6e,10,51),\
	V(3e,21,8a,f9),V(96,dd,06,3d),V(dd,3e,05,ae),V(4d,e6,bd,46),V(91,54,8d,b5),V(71,c4,5d,05),V(04,06,d4,6f),V(60,50,15,ff),\
	V(19,98,fb,24),V(d6,bd,e9,97),V(89,40,43,cc),V(67,d9,9e,77),V(b0,e8,42,bd),V(07,89,8b,88),V(e7,19,5b,38),V(79,c8,ee,db),\
	V(a1,7c,0a,47),V(7c,42,0f,e9),V(f8,84,1e,c9),V(00,00,00,00),V(09,80,86,83),V(32,2b,ed,48),V(1e,11,70,ac),V(6c,5a,72,4e),\
	V(fd,0e,ff,fb),V(0f,85,38,56),V(3d,ae,d5,1e),V(36,2d,39,27),V(0a,0f,d9,64),V(68,5c,a6,21),V(9b,5b,54,d1),V(24,36,2e,3a),\
	V(0c,0a,67,b1),V(93,57,e7,0f),V(b4,ee,96,d2),V(1b,9b,91,9e),V(80,c0,c5,4f),V(61,dc,20,a2),V(5a,77,4b,69),V(1c,12,1a,16),\
	V(e2,93,ba,0a),V(c0,a0,2a,e5),V(3c,22,e0,43),V(12,1b,17,1d),V(0e,09,0d,0b),V(f2,8b,c7,ad),V(2d,b6,a8,b9),V(14,1e,a9,c8),\
	V(57,f1,19,85),V(af,75,07,4c),V(ee,99,dd,bb),V(a3,7f,60,fd),V(f7,01,26,9f),V(5c,72,f5,bc),V(44,66,3b,c5),V(5b,fb,7e,34),\
	V(8b,43,29,76),V(cb,23,c6,dc),V(b6,ed,fc,68),V(b8,e4,f1,63),V(d7,31,dc,ca),V(42,63,85,10),V(13,97,22,40),V(84,c6,11,20),\
	V(85,4a,24,7d),V(d2,bb,3d,f8),V(ae,f9,32,11),V(c7,29,a1,6d),V(1d,9e,2f,4b),V(dc,b2,30,f3),V(0d,86,52,ec),V(77,c1,e3,d0),\
	V(2b,b3,16,6c),V(a9,70,b9,99),V(11,94,48,fa),V(47,e9,64,22),V(a8,fc,8c,c4),V(a0,f0,3f,1a),V(56,7d,2c,d8),V(22,33,90,ef),\
	V(87,49,4e,c7),V(d9,38,d1,c1),V(8c,ca,a2,fe),V(98,d4,0b,36),V(a6,f5,81,cf),V(a5,7a,de,28),V(da,b7,8e,26),V(3f,ad,bf,a4),\
	V(2c,3a,9d,e4),V(50,78,92,0d),V(6a,5f,cc,9b),V(54,7e,46,62),V(f6,8d,13,c2),V(90,d8,b8,e8),V(2e,39,f7,5e),V(82,c3,af,f5),\
	V(9f,5d,80,be),V(69,d0,93,7c),V(6f,d5,2d,a9),V(cf,25,12,b3),V(c8,ac,99,3b),V(10,18,7d,a7),V(e8,9c,63,6e),V(db,3b,bb,7b),\
	V(cd,26,78,09),V(6e,59,18,f4),V(ec,9a,b7,01),V(83,4f,9a,a8),V(e6,95,6e,65),V(aa,ff,e6,7e),V(21,bc,cf,08),V(ef,15,e8,e6),\
	V(ba,e7,9b,d9),V(4a,6f,36,ce),V(ea,9f,09,d4),V(29,b0,7c,d6),V(31,a4,b2,af),V(2a,3f,23,31),V(c6,a5,94,30),V(35,a2,66,c0),\
	V(74,4e,bc,37),V(fc,82,ca,a6),V(e0,90,d0,b0),V(33,a7,d8,15),V(f1,04,98,4a),V(41,ec,da,f7),V(7f,cd,50,0e),V(17,91,f6,2f),\
	V(76,4d,d6,8d),V(43,ef,b0,4d),V(cc,aa,4d,54),V(e4,96,04,df),V(9e,d1,b5,e3),V(4c,6a,88,1b),V(c1,2c,1f,b8),V(46,65,51,7f),\
	V(9d,5e,ea,04),V(01,8c,35,5d),V(fa,87,74,73),V(fb,0b,41,2e),V(b3,67,1d,5a),V(92,db,d2,52),V(e9,10,56,33),V(6d,d6,47,13),\
	V(9a,d7,61,8c),V(37,a1,0c,7a),V(59,f8,14,8e),V(eb,13,3c,89),V(ce,a9,27,ee),V(b7,61,c9,35),V(e1,1c,e5,ed),V(7a,47,b1,3c),\
	V(9c,d2,df,59),V(55,f2,73,3f),V(18,14,ce,79),V(73,c7,37,bf),V(53,f7,cd,ea),V(5f,fd,aa,5b),V(df,3d,6f,14),V(78,44,db,86),\
	V(ca,af,f3,81),V(b9,68,c4,3e),V(38,24,34,2c),V(c2,a3,40,5f),V(16,1d,c3,72),V(bc,e2,25,0c),V(28,3c,49,8b),V(ff,0d,95,41),\
	V(39,a8,01,71),V(08,0c,b3,de),V(d8,b4,e4,9c),V(64,56,c1,90),V(7b,cb,84,61),V(d5,32,b6,70),V(48,6c,5c,74),V(d0,b8,57,42)

#ifdef WORDS_BIGENDIAN
#define V(a, b, c, d)	0x##a##b##c##d
#else
#define V(a, b, c, d)	0x##d##c##b##a
#endif
static const uint32_t fwdLookup0[256] = {
	AES_LOOKUP
};
static const uint32_t revLookup0[256] = {
	AES_REV_LOOKUP
};
#define FT0(v)		fwdLookup0[v]
#define RT0(v)		revLookup0[v]

#ifdef WORDS_BIGENDIAN
#ifdef RACRYPT_AES_MIN_TABLE
#define FT1(v)		((FT0(v) << 24) | (FT0(v) >> 8))
#define FT2(v)		((FT0(v) << 16) | (FT0(v) >> 16))
#define FT3(v)		((FT0(v) << 8) | (FT0(v) >> 24))
#define RT1(v)		((RT0(v) << 24) | (RT0(v) >> 8))
#define RT2(v)		((RT0(v) << 16) | (RT0(v) >> 16))
#define RT3(v)		((RT0(v) << 8) | (RT0(v) >> 24))
#else
#undef V
#define V(a, b, c, d)	0x##d##a##b##c
static const uint32_t fwdLookup1[256] = {
	AES_LOOKUP
};
static const uint32_t revLookup1[256] = {
	AES_REV_LOOKUP
};
#undef V
#define V(a, b, c, d)	0x##c##d##a##b
static const uint32_t fwdLookup2[256] = {
	AES_LOOKUP
};
static const uint32_t revLookup2[256] = {
	AES_REV_LOOKUP
};
#undef V
#define V(a, b, c, d)	0x##b##c##d##a
static const uint32_t fwdLookup3[256] = {
	AES_LOOKUP
};
static const uint32_t revLookup3[256] = {
	AES_REV_LOOKUP
};
#undef V

#define FT1(v)		fwdLookup1[v]
#define FT2(v)		fwdLookup2[v]
#define FT3(v)		fwdLookup3[v]
#define RT1(v)		revLookup1[v]
#define RT2(v)		revLookup2[v]
#define RT3(v)		revLookup3[v]
#endif

#else
#ifdef RACRYPT_AES_MIN_TABLE
#define FT1(v)		((FT0(v) >> 24) | (FT0(v) << 8))
#define FT2(v)		((FT0(v) >> 16) | (FT0(v) << 16))
#define FT3(v)		((FT0(v) >> 8) | (FT0(v) << 24))
#define RT1(v)		((RT0(v) >> 24) | (RT0(v) << 8))
#define RT2(v)		((RT0(v) >> 16) | (RT0(v) << 16))
#define RT3(v)		((RT0(v) >> 8) | (RT0(v) << 24))
#else
#undef V
#define V(a, b, c, d)	0x##c##b##a##d
static const uint32_t fwdLookup1[256] = {
	AES_LOOKUP
};
static const uint32_t revLookup1[256] = {
	AES_REV_LOOKUP
};
#undef V
#define V(a, b, c, d)	0x##b##a##d##c
static const uint32_t fwdLookup2[256] = {
	AES_LOOKUP
};
static const uint32_t revLookup2[256] = {
	AES_REV_LOOKUP
};
#undef V
#define V(a, b, c, d)	0x##a##d##c##b
static const uint32_t fwdLookup3[256] = {
	AES_LOOKUP
};
static const uint32_t revLookup3[256] = {
	AES_REV_LOOKUP
};
#undef V

#define FT1(v)		fwdLookup1[v]
#define FT2(v)		fwdLookup2[v]
#define FT3(v)		fwdLookup3[v]
#define RT1(v)		revLookup1[v]
#define RT2(v)		revLookup2[v]
#define RT3(v)		revLookup3[v]
#endif
#endif

#ifdef WORDS_BIGENDIAN
#define W2B(w, n)		(uint8_t)(w >> ((3-n)*8))
#define B2W(a, b, c, d)	( ( a << 24 ) | ( b << 16 ) | ( c << 8 ) | d )
#else
#define W2B(w, n)		(uint8_t)(w >> ((n)*8))
#define B2W(a, b, c, d)	( a | ( b << 8 ) | ( c << 16 ) | ( d << 24 ) )
#endif

static void RaAesEncryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output);
static void RaAesDecryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output);

void RaAesCheckForInstructionSet(struct RaBlockCipher* blockCipher);

int RaAesCreate(const uint8_t *key, enum RaAesKeyType keyType, enum RaBlockCipherMode opMode, struct RaAesCtx **ctxp)
{
	struct RaAesCtx *ctx;
	ctx = (struct RaAesCtx*)malloc(sizeof(struct RaAesCtx));
	if (ctx == NULL) {
		return RA_ERR_OUT_OF_MEMORY;
	}
	RaAesInit(ctx, key, keyType, opMode);

	*ctxp = ctx;

	return RA_ERR_SUCCESS;
}

void RaAesDestroy(struct RaAesCtx *ctx)
{
	if (ctx != NULL) {
		memset(ctx, 0, sizeof(struct RaAesCtx));
		free(ctx);
	}
}

void RaAesInit(struct RaAesCtx *ctx, const uint8_t *key, enum RaAesKeyType keyType, enum RaBlockCipherMode opMode)
{
	int i;

	uint32_t tmpKey;
	uint32_t *prevKey;
	uint32_t *curKey;
	uint8_t keyHold;

	RaBlockCipherInit(&ctx->blockCipher, RaAesEncryptBlock, RaAesDecryptBlock, opMode, RA_BLOCK_LEN_AES, ctx->iv, ctx->buffer);

#ifdef RACRYPT_USE_ASM_AES
	RaAesCheckForInstructionSet(&ctx->blockCipher);
#endif

	prevKey = (uint32_t*)ctx->key;

	switch (keyType)
	{
	default:
	case RA_AES_128:
#define N		(int)(RA_KEY_LEN_AES_128 / sizeof(uint32_t))		// 4
		ctx->nr = 11;
		memcpy(prevKey, key, N * sizeof(uint32_t));
		curKey = prevKey + N;
		tmpKey = prevKey[N - 1];
		for (i = 1; i < (11 * 4) / N; i++)
		{
			keyHold = ((uint8_t*)&tmpKey)[0];
			((uint8_t*)&tmpKey)[0] = (uint8_t)(s[((uint8_t*)&tmpKey)[1]] ^ rcon[i - 1]);
			((uint8_t*)&tmpKey)[1] = s[((uint8_t*)&tmpKey)[2]];
			((uint8_t*)&tmpKey)[2] = s[((uint8_t*)&tmpKey)[3]];
			((uint8_t*)&tmpKey)[3] = s[keyHold];
			tmpKey ^= prevKey[0];
			curKey[0] = tmpKey;
			tmpKey ^= prevKey[1];
			curKey[1] = tmpKey;
			tmpKey ^= prevKey[2];
			curKey[2] = tmpKey;
			tmpKey ^= prevKey[3];
			curKey[3] = tmpKey;
			curKey += N;
			prevKey += N;
		}
#undef N
		break;
	case RA_AES_192:
#define N		(int)(RA_KEY_LEN_AES_192 / sizeof(uint32_t))		// 6
		ctx->nr = 13;
		memcpy(prevKey, key, N * sizeof(uint32_t));
		curKey = prevKey + N;
		tmpKey = prevKey[N - 1];
		for (i = 1; i < (13 * 4) / N; i++)
		{
			keyHold = ((uint8_t*)&tmpKey)[0];
			((uint8_t*)&tmpKey)[0] = (uint8_t)(s[((uint8_t*)&tmpKey)[1]] ^ rcon[i - 1]);
			((uint8_t*)&tmpKey)[1] = s[((uint8_t*)&tmpKey)[2]];
			((uint8_t*)&tmpKey)[2] = s[((uint8_t*)&tmpKey)[3]];
			((uint8_t*)&tmpKey)[3] = s[keyHold];
			tmpKey ^= prevKey[0];
			curKey[0] = tmpKey;
			tmpKey ^= prevKey[1];
			curKey[1] = tmpKey;
			tmpKey ^= prevKey[2];
			curKey[2] = tmpKey;
			tmpKey ^= prevKey[3];
			curKey[3] = tmpKey;
			tmpKey ^= prevKey[4];
			curKey[4] = tmpKey;
			tmpKey ^= prevKey[5];
			curKey[5] = tmpKey;
			curKey += N;
			prevKey += N;
		}
		// 13 * 4 = 6 * 8 + 4
		keyHold = ((uint8_t*)&tmpKey)[0];
		((uint8_t*)&tmpKey)[0] = (uint8_t)(s[((uint8_t*)&tmpKey)[1]] ^ rcon[i - 1]);
		((uint8_t*)&tmpKey)[1] = s[((uint8_t*)&tmpKey)[2]];
		((uint8_t*)&tmpKey)[2] = s[((uint8_t*)&tmpKey)[3]];
		((uint8_t*)&tmpKey)[3] = s[keyHold];
		tmpKey ^= prevKey[0];
		curKey[0] = tmpKey;
		tmpKey ^= prevKey[1];
		curKey[1] = tmpKey;
		tmpKey ^= prevKey[2];
		curKey[2] = tmpKey;
		tmpKey ^= prevKey[3];
		curKey[3] = tmpKey;
#undef N
		break;
	case RA_AES_256:
#define N		(int)(RA_KEY_LEN_AES_256 / sizeof(uint32_t))		// 8
		ctx->nr = 15;
		memcpy(prevKey, key, N * sizeof(uint32_t));
		curKey = prevKey + N;
		tmpKey = prevKey[N - 1];
		for (i = 1; i < (15 * 4) / N; i++)
		{
			keyHold = ((uint8_t*)&tmpKey)[0];
			((uint8_t*)&tmpKey)[0] = (uint8_t)(s[((uint8_t*)&tmpKey)[1]] ^ rcon[i - 1]);
			((uint8_t*)&tmpKey)[1] = s[((uint8_t*)&tmpKey)[2]];
			((uint8_t*)&tmpKey)[2] = s[((uint8_t*)&tmpKey)[3]];
			((uint8_t*)&tmpKey)[3] = s[keyHold];
			tmpKey ^= prevKey[0];
			curKey[0] = tmpKey;
			tmpKey ^= prevKey[1];
			curKey[1] = tmpKey;
			tmpKey ^= prevKey[2];
			curKey[2] = tmpKey;
			tmpKey ^= prevKey[3];
			curKey[3] = tmpKey;

			((uint8_t*)&tmpKey)[0] = s[((uint8_t*)&tmpKey)[0]];
			((uint8_t*)&tmpKey)[1] = s[((uint8_t*)&tmpKey)[1]];
			((uint8_t*)&tmpKey)[2] = s[((uint8_t*)&tmpKey)[2]];
			((uint8_t*)&tmpKey)[3] = s[((uint8_t*)&tmpKey)[3]];
			tmpKey ^= prevKey[4];
			curKey[4] = tmpKey;
			tmpKey ^= prevKey[5];
			curKey[5] = tmpKey;
			tmpKey ^= prevKey[6];
			curKey[6] = tmpKey;
			tmpKey ^= prevKey[7];
			curKey[7] = tmpKey;
			curKey += N;
			prevKey += N;
		}
		// 15 * 4 = 8 * 7 + 4
		keyHold = ((uint8_t*)&tmpKey)[0];
		((uint8_t*)&tmpKey)[0] = (uint8_t)(s[((uint8_t*)&tmpKey)[1]] ^ rcon[i - 1]);
		((uint8_t*)&tmpKey)[1] = s[((uint8_t*)&tmpKey)[2]];
		((uint8_t*)&tmpKey)[2] = s[((uint8_t*)&tmpKey)[3]];
		((uint8_t*)&tmpKey)[3] = s[keyHold];
		tmpKey ^= prevKey[0];
		curKey[0] = tmpKey;
		tmpKey ^= prevKey[1];
		curKey[1] = tmpKey;
		tmpKey ^= prevKey[2];
		curKey[2] = tmpKey;
		tmpKey ^= prevKey[3];
		curKey[3] = tmpKey;
#undef N
		break;
	}
	curKey = (uint32_t*)ctx->rev_key;
	prevKey = (uint32_t*)ctx->key;

	// rev_key = key * rev_mix_col = rev_sub(sub(key)) * rev_mix_col = rev_lookup(sub(key))
	for (i = 0; i < ctx->nr; i++) {
#define I(x,y)		s[W2B( prevKey[x], y )]
		curKey[0] = RT0(I(0, 0)) ^ RT1(I(0, 1)) ^ RT2(I(0, 2)) ^ RT3(I(0, 3));
		curKey[1] = RT0(I(1, 0)) ^ RT1(I(1, 1)) ^ RT2(I(1, 2)) ^ RT3(I(1, 3));
		curKey[2] = RT0(I(2, 0)) ^ RT1(I(2, 1)) ^ RT2(I(2, 2)) ^ RT3(I(2, 3));
		curKey[3] = RT0(I(3, 0)) ^ RT1(I(3, 1)) ^ RT2(I(3, 2)) ^ RT3(I(3, 3));
#undef I
		curKey += 4;
		prevKey += 4;
	}
}

inline static void AesFwdProcess(uint32_t *i, uint32_t *o, uint32_t *key)
{
	// sub byte, shift row, mix col, add key
	// (shift_sub(input) * mix_col) + key
	// = lookup(shift(input)) + key
	o[0] = FT0(W2B(i[0], 0)) ^ FT1(W2B(i[1], 1)) ^ FT2(W2B(i[2], 2)) ^ FT3(W2B(i[3], 3)) ^ key[0];
	o[1] = FT0(W2B(i[1], 0)) ^ FT1(W2B(i[2], 1)) ^ FT2(W2B(i[3], 2)) ^ FT3(W2B(i[0], 3)) ^ key[1];
	o[2] = FT0(W2B(i[2], 0)) ^ FT1(W2B(i[3], 1)) ^ FT2(W2B(i[0], 2)) ^ FT3(W2B(i[1], 3)) ^ key[2];
	o[3] = FT0(W2B(i[3], 0)) ^ FT1(W2B(i[0], 1)) ^ FT2(W2B(i[1], 2)) ^ FT3(W2B(i[2], 3)) ^ key[3];
}

inline static void AesRevProcess(uint32_t *i, uint32_t *o, uint32_t *rev_key)
{
	// rev_shift row, rev_sub byte, add key, rev_mix col
	// (rev_shift_sub(input) + key) * rev_mix_col = (rev_shift_sub(input) * rev_mix_col) + (key * rev_mix_col)
	// = (rev_shift_sub(input) * rev_mix_col) + rev_key = rev_lookup(rev_shift(input)) + rev_key
	o[0] = RT0(W2B(i[0], 0)) ^ RT1(W2B(i[3], 1)) ^ RT2(W2B(i[2], 2)) ^ RT3(W2B(i[1], 3)) ^ rev_key[0];
	o[1] = RT0(W2B(i[1], 0)) ^ RT1(W2B(i[0], 1)) ^ RT2(W2B(i[3], 2)) ^ RT3(W2B(i[2], 3)) ^ rev_key[1];
	o[2] = RT0(W2B(i[2], 0)) ^ RT1(W2B(i[1], 1)) ^ RT2(W2B(i[0], 2)) ^ RT3(W2B(i[3], 3)) ^ rev_key[2];
	o[3] = RT0(W2B(i[3], 0)) ^ RT1(W2B(i[2], 1)) ^ RT2(W2B(i[1], 2)) ^ RT3(W2B(i[0], 3)) ^ rev_key[3];
}

inline static void AesFwdSubByteShiftRow(uint32_t *i, uint32_t *o)
{
	o[0] = B2W(s[W2B(i[0], 0)], s[W2B(i[1], 1)], s[W2B(i[2], 2)], s[W2B(i[3], 3)]);
	o[1] = B2W(s[W2B(i[1], 0)], s[W2B(i[2], 1)], s[W2B(i[3], 2)], s[W2B(i[0], 3)]);
	o[2] = B2W(s[W2B(i[2], 0)], s[W2B(i[3], 1)], s[W2B(i[0], 2)], s[W2B(i[1], 3)]);
	o[3] = B2W(s[W2B(i[3], 0)], s[W2B(i[0], 1)], s[W2B(i[1], 2)], s[W2B(i[2], 3)]);
}

inline static void AesRevSubByteShiftRow(uint32_t *i, uint32_t *o)
{
	o[0] = B2W(rev_s[W2B(i[0], 0)], rev_s[W2B(i[3], 1)], rev_s[W2B(i[2], 2)], rev_s[W2B(i[1], 3)]);
	o[1] = B2W(rev_s[W2B(i[1], 0)], rev_s[W2B(i[0], 1)], rev_s[W2B(i[3], 2)], rev_s[W2B(i[2], 3)]);
	o[2] = B2W(rev_s[W2B(i[2], 0)], rev_s[W2B(i[1], 1)], rev_s[W2B(i[0], 2)], rev_s[W2B(i[3], 3)]);
	o[3] = B2W(rev_s[W2B(i[3], 0)], rev_s[W2B(i[2], 1)], rev_s[W2B(i[1], 2)], rev_s[W2B(i[0], 3)]);
}

static void RaAesEncryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output)
{
	int round;
	uint32_t tmpData[4];
	uint32_t tmpData2[4];

	struct RaAesCtx *ctx;
	ctx = CHILD_OF(blockCipher, struct RaAesCtx, blockCipher);

	memcpy(tmpData, input, RA_BLOCK_LEN_AES);

	// add key
	tmpData[0] ^= ctx->key[0][0];
	tmpData[1] ^= ctx->key[0][1];
	tmpData[2] ^= ctx->key[0][2];
	tmpData[3] ^= ctx->key[0][3];

	for (round = 1; round < ctx->nr - 2; round += 2) {
		// sub byte, shift row, mix col, add key
		AesFwdProcess(tmpData, tmpData2, ctx->key[round]);
		AesFwdProcess(tmpData2, tmpData, ctx->key[round + 1]);
	}
	// sub byte, shift row, mix col, add key
	AesFwdProcess(tmpData, tmpData2, ctx->key[round]);	// ctx->nr - 2
	round++;

	// sub byte, shift row
	AesFwdSubByteShiftRow(tmpData2, tmpData);

	// add key
	tmpData[0] ^= ctx->key[round][0];
	tmpData[1] ^= ctx->key[round][1];
	tmpData[2] ^= ctx->key[round][2];
	tmpData[3] ^= ctx->key[round][3];

	memcpy(output, tmpData, 16);
}

static void RaAesDecryptBlock(struct RaBlockCipher *blockCipher, const uint8_t *input, uint8_t *output)
{
	int round;
	uint32_t tmpData[4];
	uint32_t tmpData2[4];

	struct RaAesCtx *ctx;
	ctx = CHILD_OF(blockCipher, struct RaAesCtx, blockCipher);

	memcpy(tmpData, input, RA_BLOCK_LEN_AES);

	round = ctx->nr - 1;
	// rev_add key
	tmpData[0] ^= ctx->key[round][0];
	tmpData[1] ^= ctx->key[round][1];
	tmpData[2] ^= ctx->key[round][2];
	tmpData[3] ^= ctx->key[round][3];

	for (round = round - 1; round >= 2; round -= 2) {
		// rev_shift row, rev_sub byte, rev_add key, rev_mix col
		AesRevProcess(tmpData, tmpData2, ctx->rev_key[round]);
		AesRevProcess(tmpData2, tmpData, ctx->rev_key[round - 1]);
	}
	// round 1
	// rev_shift row, rev_sub byte, rev_add key, rev_mix col
	AesRevProcess(tmpData, tmpData2, ctx->rev_key[round]);

	// rev_shift row, rev_sub byte
	AesRevSubByteShiftRow(tmpData2, tmpData);

	// rev_add key
	tmpData[0] ^= ctx->key[0][0];
	tmpData[1] ^= ctx->key[0][1];
	tmpData[2] ^= ctx->key[0][2];
	tmpData[3] ^= ctx->key[0][3];

	memcpy(output, tmpData, 16);
}


int RaAesEncrypt(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output)
{
	return RaBlockCipherEncrypt(&ctx->blockCipher, input, length, output);
}

int RaAesEncryptFinal(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType)
{
	return RaBlockCipherEncryptFinal(&ctx->blockCipher, input, length, output, paddingType);
}

int RaAesDecrypt(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output)
{
	return RaBlockCipherDecrypt(&ctx->blockCipher, input, length, output);
}

int RaAesDecryptFinal(struct RaAesCtx *ctx, const uint8_t *input, int length, uint8_t *output, enum RaBlockCipherPaddingType paddingType)
{
	return RaBlockCipherDecryptFinal(&ctx->blockCipher, input, length, output, paddingType);
}

void RaAesSetIV(struct RaAesCtx *ctx, const uint8_t iv[16])
{
	RaBlockCipherSetIV(&ctx->blockCipher, iv);
}

void RaAesGetIV(struct RaAesCtx *ctx, /*out*/uint8_t iv[16])
{
	RaBlockCipherGetIV(&ctx->blockCipher, iv);
}

#undef FT0
#undef RT0
#undef W2B
#undef B2W
