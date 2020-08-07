/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void printHex( char* prefix, uint8_t* data, int len );
//static void printHexData( char* prefix, uint8_t* data, int len );

static uint8_t prime[] = {
0x91, 0x33, 0xa5, 0x78, 0x41, 0xc5, 0xeb, 0xc8, 0x92, 0xa3, 0x67, 0x4a, 0x42, 0xda, 0x13, 0x1e,
0x1a, 0x49, 0x66, 0x5d, 0x13, 0x78, 0x60, 0x42, 0xa6, 0x21, 0xae, 0xba, 0x2e, 0xc0, 0x61, 0x1e,
0x4e, 0x6d, 0x38, 0x9c, 0x9f, 0xb9, 0x78, 0x45, 0xfc, 0xe4, 0x69, 0x93, 0x05, 0x24, 0x07, 0x50,
0xb2, 0x13, 0xec, 0x2e, 0xee, 0x1d, 0x9b, 0x80, 0x2b, 0x29, 0x7d, 0xb5, 0x7f, 0x9c, 0x1b, 0x65
};

static uint8_t pub[] = {
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0x98, 0x52, 0xcf, 0xb3, 0x49, 0xe4, 0xc6, 0x35, 0x01, 0xea, 0x51, 0x24, 0xb6, 0x2b, 0xd9,
	0x6f, 0xac, 0x2e, 0x46, 0xa4, 0xcb, 0xc0, 0x87, 0x45, 0xf8, 0xef, 0x44, 0x6e, 0x49, 0x54, 0x33,
	0xec, 0xf5, 0x56, 0x19, 0xfc, 0xff, 0x9e, 0x57, 0xf0, 0x0a, 0x2e, 0xa1, 0x9a, 0x69, 0x55, 0x59,
	0x8c, 0xfd, 0xe5, 0xa9, 0xeb, 0xd0, 0xc0, 0x4b, 0xe9, 0xe4, 0x10, 0x2c, 0x25, 0xdf, 0xa8, 0xe7,
	0x53, 0x8c, 0x1b, 0x7f, 0x46, 0x97, 0xee, 0x88, 0x11, 0xfa, 0x15, 0xe7, 0x6b, 0x60, 0x76, 0x7d,
	0x08, 0xe6, 0x1d, 0x3d, 0xbf, 0x71, 0x3f, 0x33, 0xc9, 0x0f, 0xd0, 0x58, 0x4e, 0x5b, 0x78, 0x08,
	0xfc, 0xdf, 0xcc, 0xe1, 0xb4, 0xfc, 0x8e, 0xec, 0x98, 0x3d, 0xbd, 0xc9, 0xee, 0x4a, 0x02, 0xb6,
	0x56, 0x4a, 0x8a, 0xbd, 0xc1, 0xab, 0xdd, 0xc0, 0xdb, 0x7b, 0x32, 0x0f, 0x69, 0x74, 0x34, 0xdd,
	0xbc, 0x5b, 0xc7, 0x89, 0x63, 0x60, 0x83, 0xc7, 0x9e, 0x8f, 0x1a, 0x05, 0xc6, 0xc8, 0xd5, 0xc4,
	0xc7, 0x5a, 0x7f, 0xc2, 0x47, 0x3d, 0xe0, 0xca, 0x84, 0xc4, 0x1d, 0x8e, 0xd9, 0x41, 0x6f, 0x5e,
	0x8a, 0x8d, 0x87, 0xca, 0xb7, 0x87, 0x95, 0x03, 0x47, 0xb1, 0x39, 0x2e, 0xcb, 0x87, 0xd7, 0x73,
	0x2b, 0x9f, 0x38, 0x23, 0x08, 0x21, 0x1f, 0x9a, 0x31, 0xf6, 0xb1, 0x76, 0x11, 0xab, 0x27, 0x3e,
	0x89, 0x6e, 0x86, 0x2b, 0x42, 0xae, 0xc7, 0xd1, 0xbe, 0xa4, 0xa0, 0xb0, 0x8a, 0x26, 0xd9, 0x12,
	0x44, 0x90, 0x0a, 0xae, 0xba, 0x17, 0x2e, 0xd5, 0xdc, 0x48, 0xf9, 0x85, 0xad, 0x1a, 0x98, 0x01,
	0x48, 0xce, 0x20, 0xb0, 0x6d, 0x4f, 0x9f, 0xdc, 0xd2, 0x43, 0x7a, 0x16, 0xab, 0x6e, 0x93, 0x41,
	0x1a, 0xad, 0x18, 0x85, 0xbc, 0x36, 0x75, 0xfe, 0x56, 0x3a, 0x65, 0x4e, 0xe5, 0x47, 0xe3, 0x43,
	0x3f, 0x02, 0x03, 0x01, 0x00, 0x01
};

static uint8_t priv[] = {
	0x30, 0x82, 0x04, 0xbd, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
	0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa7, 0x30, 0x82, 0x04, 0xa3, 0x02, 0x01,
	0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0x98, 0x52, 0xcf, 0xb3, 0x49, 0xe4, 0xc6, 0x35, 0x01, 0xea,
	0x51, 0x24, 0xb6, 0x2b, 0xd9, 0x6f, 0xac, 0x2e, 0x46, 0xa4, 0xcb, 0xc0, 0x87, 0x45, 0xf8, 0xef,
	0x44, 0x6e, 0x49, 0x54, 0x33, 0xec, 0xf5, 0x56, 0x19, 0xfc, 0xff, 0x9e, 0x57, 0xf0, 0x0a, 0x2e,
	0xa1, 0x9a, 0x69, 0x55, 0x59, 0x8c, 0xfd, 0xe5, 0xa9, 0xeb, 0xd0, 0xc0, 0x4b, 0xe9, 0xe4, 0x10,
	0x2c, 0x25, 0xdf, 0xa8, 0xe7, 0x53, 0x8c, 0x1b, 0x7f, 0x46, 0x97, 0xee, 0x88, 0x11, 0xfa, 0x15,
	0xe7, 0x6b, 0x60, 0x76, 0x7d, 0x08, 0xe6, 0x1d, 0x3d, 0xbf, 0x71, 0x3f, 0x33, 0xc9, 0x0f, 0xd0,
	0x58, 0x4e, 0x5b, 0x78, 0x08, 0xfc, 0xdf, 0xcc, 0xe1, 0xb4, 0xfc, 0x8e, 0xec, 0x98, 0x3d, 0xbd,
	0xc9, 0xee, 0x4a, 0x02, 0xb6, 0x56, 0x4a, 0x8a, 0xbd, 0xc1, 0xab, 0xdd, 0xc0, 0xdb, 0x7b, 0x32,
	0x0f, 0x69, 0x74, 0x34, 0xdd, 0xbc, 0x5b, 0xc7, 0x89, 0x63, 0x60, 0x83, 0xc7, 0x9e, 0x8f, 0x1a,
	0x05, 0xc6, 0xc8, 0xd5, 0xc4, 0xc7, 0x5a, 0x7f, 0xc2, 0x47, 0x3d, 0xe0, 0xca, 0x84, 0xc4, 0x1d,
	0x8e, 0xd9, 0x41, 0x6f, 0x5e, 0x8a, 0x8d, 0x87, 0xca, 0xb7, 0x87, 0x95, 0x03, 0x47, 0xb1, 0x39,
	0x2e, 0xcb, 0x87, 0xd7, 0x73, 0x2b, 0x9f, 0x38, 0x23, 0x08, 0x21, 0x1f, 0x9a, 0x31, 0xf6, 0xb1,
	0x76, 0x11, 0xab, 0x27, 0x3e, 0x89, 0x6e, 0x86, 0x2b, 0x42, 0xae, 0xc7, 0xd1, 0xbe, 0xa4, 0xa0,
	0xb0, 0x8a, 0x26, 0xd9, 0x12, 0x44, 0x90, 0x0a, 0xae, 0xba, 0x17, 0x2e, 0xd5, 0xdc, 0x48, 0xf9,
	0x85, 0xad, 0x1a, 0x98, 0x01, 0x48, 0xce, 0x20, 0xb0, 0x6d, 0x4f, 0x9f, 0xdc, 0xd2, 0x43, 0x7a,
	0x16, 0xab, 0x6e, 0x93, 0x41, 0x1a, 0xad, 0x18, 0x85, 0xbc, 0x36, 0x75, 0xfe, 0x56, 0x3a, 0x65,
	0x4e, 0xe5, 0x47, 0xe3, 0x43, 0x3f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x19,
	0x07, 0x02, 0x39, 0x63, 0x1a, 0xc3, 0xb6, 0x51, 0xea, 0x3e, 0x0a, 0xda, 0x23, 0xba, 0x46, 0x2e,
	0xf4, 0x2b, 0x87, 0x48, 0x33, 0x0a, 0x06, 0xe5, 0x2f, 0xea, 0xfe, 0x73, 0xed, 0xf1, 0xda, 0x2d,
	0x35, 0x48, 0x6f, 0xd9, 0x50, 0x1b, 0x02, 0xc5, 0xa9, 0x83, 0xc3, 0xeb, 0x2a, 0xaa, 0xdc, 0x0f,
	0x9b, 0x7c, 0x9f, 0xd2, 0x5c, 0xc6, 0x1c, 0x57, 0xec, 0x90, 0x54, 0x68, 0xbb, 0x47, 0xc6, 0xe2,
	0x6e, 0x62, 0x2b, 0x27, 0x2b, 0x7a, 0x0f, 0xfa, 0x17, 0x3f, 0x3e, 0xd5, 0x4a, 0xa2, 0xa0, 0xa3,
	0xae, 0x8a, 0x46, 0xba, 0x44, 0xb8, 0x2d, 0x80, 0xfb, 0xaa, 0x86, 0xb5, 0x60, 0xb3, 0x99, 0x58,
	0xec, 0x40, 0xe9, 0x8b, 0xd5, 0xaf, 0xea, 0x13, 0xba, 0xeb, 0x42, 0xcb, 0xc6, 0x46, 0x4f, 0x47,
	0x50, 0x24, 0x7d, 0x7d, 0xcf, 0xa1, 0xb0, 0x6e, 0x3d, 0x7b, 0x6a, 0xc8, 0x3d, 0x27, 0x71, 0x5a,
	0x79, 0x87, 0x73, 0x1f, 0x44, 0xc7, 0xd8, 0x10, 0x9d, 0x6f, 0xa1, 0x04, 0x25, 0xbc, 0x7a, 0x13,
	0x34, 0x73, 0x31, 0xa7, 0xd9, 0xf9, 0x62, 0x9a, 0x4a, 0x2f, 0xf0, 0xcc, 0xb6, 0x27, 0x0f, 0x8a,
	0x8a, 0xe6, 0xa0, 0x5a, 0xd9, 0x23, 0x54, 0xc3, 0x64, 0xe7, 0x98, 0x37, 0xc0, 0x61, 0x3c, 0x53,
	0x75, 0xd4, 0x76, 0xbc, 0x92, 0x91, 0xb2, 0x4b, 0x10, 0x67, 0x43, 0x9f, 0xbd, 0xa1, 0xba, 0x38,
	0x75, 0x89, 0x06, 0x4c, 0xf1, 0xa0, 0xb0, 0x50, 0xf1, 0xf8, 0xdb, 0x7d, 0x53, 0x13, 0xbc, 0x66,
	0x97, 0xc0, 0xe0, 0x73, 0x68, 0x76, 0x84, 0x76, 0x31, 0xad, 0x71, 0x01, 0x26, 0x3a, 0xe9, 0xa0,
	0xf2, 0xf4, 0x73, 0x8f, 0x29, 0x7f, 0xcb, 0x55, 0x35, 0x7c, 0x5d, 0x70, 0x51, 0x81, 0x38, 0xc7,
	0x5e, 0x3b, 0xe0, 0xdd, 0xd6, 0x8c, 0xf6, 0x44, 0x4b, 0x31, 0xc5, 0xca, 0xcf, 0x91, 0x81, 0x02,
	0x81, 0x81, 0x00, 0xca, 0x8a, 0x99, 0xd4, 0x68, 0xae, 0xc8, 0x49, 0xd1, 0x48, 0x8f, 0xe0, 0x32,
	0x05, 0x9d, 0x8f, 0xf1, 0x16, 0x7c, 0x92, 0x78, 0xb3, 0xb8, 0x82, 0x2b, 0xae, 0x8c, 0xb8, 0x71,
	0x91, 0xd3, 0xcf, 0xa4, 0xae, 0x6e, 0x20, 0x49, 0x33, 0x00, 0xbc, 0x79, 0x30, 0xe9, 0xdb, 0xb9,
	0x41, 0x97, 0xbe, 0xe9, 0x3f, 0x59, 0x5c, 0xc3, 0x2d, 0x9d, 0x03, 0x7a, 0xeb, 0xc8, 0x68, 0x14,
	0x7a, 0x37, 0xcf, 0xcc, 0x78, 0x8c, 0xf3, 0x7d, 0x41, 0x87, 0xe3, 0xe0, 0x40, 0xaf, 0xd0, 0x8f,
	0x33, 0xa9, 0x92, 0xee, 0x73, 0xfa, 0x61, 0x62, 0x28, 0x6c, 0xa5, 0xb6, 0xd1, 0xad, 0x8a, 0x98,
	0x45, 0x54, 0xbc, 0x30, 0xf3, 0x49, 0x1d, 0xe3, 0xee, 0x47, 0xe6, 0x8e, 0xb2, 0xd0, 0x8a, 0x1b,
	0x09, 0xa9, 0x96, 0x94, 0xbc, 0xd7, 0x99, 0xdf, 0x3a, 0xf4, 0x72, 0x85, 0xd4, 0x28, 0x9f, 0xbd,
	0x66, 0xab, 0x8b, 0x02, 0x81, 0x81, 0x00, 0xc0, 0x87, 0x10, 0xbb, 0x50, 0x46, 0x2e, 0xf4, 0x4d,
	0x79, 0x34, 0x82, 0xd6, 0x8e, 0xb6, 0x3f, 0x06, 0xed, 0x1d, 0x3d, 0x72, 0x5b, 0x11, 0x54, 0xab,
	0xe8, 0xde, 0x7d, 0xb4, 0xb1, 0x53, 0xd1, 0xb1, 0xd3, 0x3f, 0x69, 0xf1, 0x51, 0xb2, 0x55, 0x0b,
	0x4c, 0x18, 0xe1, 0x5e, 0x2a, 0xc1, 0x41, 0x9d, 0x93, 0x6a, 0xa7, 0x89, 0xd9, 0x4e, 0x16, 0x98,
	0x9e, 0x10, 0x16, 0x36, 0x68, 0x85, 0x96, 0x65, 0x32, 0x7b, 0x08, 0x4c, 0xb9, 0x51, 0x09, 0x22,
	0xa8, 0x0b, 0x0e, 0x45, 0x84, 0x4a, 0x46, 0x7f, 0x41, 0x52, 0x03, 0x04, 0xb1, 0xba, 0xb0, 0x5f,
	0x6b, 0x16, 0x12, 0xf2, 0x5d, 0x6b, 0x20, 0x4d, 0x60, 0xa0, 0x97, 0xfd, 0x12, 0x39, 0x83, 0x5c,
	0x82, 0x62, 0xf8, 0x52, 0xcd, 0x43, 0x96, 0x26, 0x44, 0x04, 0xe2, 0x34, 0x70, 0x6a, 0x95, 0x50,
	0xde, 0xfc, 0x06, 0x7a, 0x62, 0x0d, 0x9d, 0x02, 0x81, 0x80, 0x4f, 0x7f, 0xef, 0xb9, 0x8c, 0x0d,
	0x6e, 0xd8, 0x6a, 0xa9, 0x4c, 0xaf, 0xf7, 0x72, 0x74, 0xd2, 0x17, 0x13, 0x78, 0x7a, 0x15, 0x9e,
	0x95, 0x81, 0xa2, 0x9b, 0xb4, 0xe8, 0x80, 0xcb, 0x78, 0x94, 0x3c, 0x53, 0xab, 0x2e, 0x49, 0x0d,
	0x17, 0xf0, 0xe2, 0xb0, 0xec, 0x5a, 0x2e, 0x71, 0x2c, 0x9a, 0xe6, 0xfa, 0xd2, 0x9c, 0xb2, 0x8f,
	0xa8, 0xdd, 0xc0, 0xd5, 0xe3, 0xa7, 0xd6, 0xc1, 0xd2, 0x3e, 0x62, 0x47, 0xbf, 0x2b, 0xa3, 0xb2,
	0xa1, 0x20, 0x34, 0xd9, 0xaf, 0x28, 0xf1, 0xcc, 0x99, 0x76, 0xee, 0xd9, 0xdf, 0x21, 0x72, 0x61,
	0xe3, 0xa3, 0x78, 0x0a, 0xfd, 0x4f, 0x35, 0x4d, 0xa1, 0x60, 0xec, 0xe5, 0xd1, 0x81, 0x46, 0x02,
	0x35, 0x7e, 0xad, 0xec, 0x4a, 0x26, 0xab, 0x4e, 0x33, 0x9e, 0xc3, 0x6b, 0x0c, 0x45, 0x7d, 0x75,
	0xaa, 0x95, 0x79, 0x2a, 0x39, 0x77, 0xd9, 0xe3, 0xfe, 0xd9, 0x02, 0x81, 0x81, 0x00, 0xb2, 0x28,
	0x0a, 0x16, 0x9b, 0x78, 0xe6, 0x98, 0x51, 0x5c, 0xb8, 0x77, 0xde, 0x5d, 0x9f, 0x4d, 0x81, 0x76,
	0x47, 0x99, 0x85, 0xc9, 0xb9, 0xa6, 0xd5, 0x91, 0x9e, 0xd9, 0x4a, 0x2c, 0xd1, 0xb8, 0x78, 0xca,
	0x57, 0xa3, 0x0c, 0x99, 0x21, 0xe1, 0xca, 0x9b, 0x77, 0x66, 0x8d, 0x02, 0x19, 0x65, 0x43, 0x90,
	0x97, 0xa0, 0x43, 0x52, 0x60, 0x0d, 0x4e, 0xda, 0xed, 0x5d, 0xf0, 0xa9, 0x15, 0xfd, 0x0e, 0xd6,
	0x00, 0xbd, 0xb4, 0x69, 0xc4, 0x10, 0x25, 0x0e, 0xc5, 0x74, 0x46, 0x65, 0xdd, 0x69, 0x90, 0xf6,
	0x7c, 0x12, 0xa8, 0xf4, 0x62, 0x22, 0x35, 0x99, 0xdd, 0x8a, 0x58, 0xd6, 0x93, 0x7c, 0x07, 0xbe,
	0x43, 0xbd, 0x81, 0x84, 0xac, 0xcd, 0xde, 0xfc, 0x14, 0xe3, 0x5f, 0x93, 0xec, 0x57, 0xf4, 0x3e,
	0xfb, 0x19, 0xeb, 0x96, 0x9f, 0x3a, 0x5e, 0xe4, 0x88, 0xe8, 0xe1, 0xb4, 0xfc, 0x8d, 0x02, 0x81,
	0x80, 0x10, 0xff, 0xf1, 0x1d, 0xd0, 0xb1, 0x21, 0x62, 0x4e, 0x7b, 0x32, 0x40, 0x01, 0x97, 0x26,
	0x52, 0xdb, 0x00, 0xfe, 0x2d, 0x45, 0xfe, 0x98, 0xc8, 0x0c, 0xac, 0x0e, 0x25, 0xe9, 0xe8, 0x14,
	0xb1, 0xc1, 0xf7, 0x37, 0x3d, 0x93, 0x96, 0x41, 0xa3, 0xa0, 0x35, 0x29, 0x02, 0x0c, 0x94, 0xe4,
	0xe3, 0x44, 0x71, 0xef, 0xaa, 0xb5, 0xcc, 0xc2, 0x30, 0x93, 0xf1, 0x5d, 0x9c, 0x22, 0x02, 0x18,
	0x5a, 0x38, 0xaf, 0x3d, 0xf9, 0x5e, 0x5a, 0xdf, 0xf6, 0x6b, 0xcf, 0x29, 0xc2, 0x2a, 0x16, 0x99,
	0xab, 0x46, 0xb0, 0x0b, 0xc6, 0xb8, 0x85, 0xf1, 0x2e, 0x77, 0xa3, 0x71, 0xa5, 0x1e, 0x9a, 0x22,
	0x28, 0xfa, 0xc2, 0x36, 0x9f, 0x52, 0xd5, 0xd2, 0xd2, 0x78, 0x73, 0xe5, 0x6e, 0x86, 0xa1, 0xf2,
	0xdd, 0x0c, 0x5c, 0x5d, 0x67, 0xd9, 0x24, 0x15, 0x92, 0xa8, 0x76, 0xd0, 0x6c, 0x78, 0xa1, 0x3f,
	0xcc
};

static uint8_t message[] = "Hello, World!!!.";

static void PrintTime(long elapsed)
{
	int h, m, s, ms;
	ms = elapsed % 1000;
	elapsed /= 1000;
	s = elapsed % 60;
	elapsed /= 60;
	m = elapsed % 60;
	elapsed /= 60;
	h = elapsed;
	printf("%02d:%02d:%02d.%03d\n", h, m, s, ms);
}

static int primeProgress(int count, void* pcount)
{
	printf(".");
	fflush(stdout);
	*(int*)pcount = count;
	return 0;
}

#ifdef _WIN32
#include <windows.h>
struct Timer
{
	LARGE_INTEGER count;
	LARGE_INTEGER freq;
};
static void InitTimer(struct Timer *t)
{
	QueryPerformanceFrequency(&t->freq);
	QueryPerformanceCounter(&t->count);
}

static long GetElapsedTimeInMillisec(struct Timer *t)
{
	LARGE_INTEGER now;
	LONGLONG elapsed;
	QueryPerformanceCounter(&now);
	elapsed = now.QuadPart - t->count.QuadPart;
	return (long)(elapsed * 1000 / t->freq.QuadPart);
}

static void PrintElapsed(struct Timer *t, char* prefix)
{
	long elapsed = GetElapsedTimeInMillisec(t);
	printf("%s", prefix);
	PrintTime(elapsed);
}

#else
struct Timer
{
	struct timespec ts;
};
void InitTimer(struct Timer *t)
{
	clock_gettime(CLOCK_MONOTONIC, &t->ts);
}
long GetElapsedTimeInMillisec(struct Timer *t)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	long millisec;
	millisec = (long)(ts.tv_sec - t->ts.tv_sec) * 1000;
	millisec += (ts.tv_nsec - t->ts.tv_nsec) / 1000000;
	return millisec;
}

void PrintElapsed(struct Timer *t, char* message)
{
	long elapsed = GetElapsedTimeInMillisec(t);
	printf("%s", message);
	PrintTime(elapsed);
}
#endif

int test1()
{
	int result;
	struct BigNumber *bn1 = NULL;
	struct BigNumber *bn2 = NULL;
	struct BigNumber *bn3 = NULL;
	struct BigNumber *r = NULL;
	struct BigNumber *m = NULL;
	struct BigNumber *n = NULL;
	int count;
	uint8_t buffer[2048 / 8 + 1];

	bn1 = BnNewW(0);
	bn2 = BnNewW(0);
	bn3 = BnNewW(0);
	r = BnNewW(0);
	m = BnNewW(0);
	n = BnNewW(0);

	if (bn1 == NULL || bn2 == NULL || bn3 == NULL ||
		r == NULL || m == NULL || n == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	BnSetInt64(bn1, 135);

	count = BnToByteArray(bn1, buffer, sizeof(buffer));
	if (BnToByteArray(bn1, NULL, 0) != count) {
		printf("error BnToByteArray(bn, NULL, 0) get count\n");
	}
	BnSetByteArray(bn2, buffer, count);
	if (BnCmp(bn1, bn2) != 0) {
		printf("error BnToByteArray() or BnSetByteArray()\n");
	}
	BnSetUByteArray( bn2, buffer, count );
	printHex( "hex=", buffer, count );
	BnToFixedByteArray( bn2, buffer, 1 );
	printHex( "fixed_hex=", buffer, 1 );

	//BnSetInt(bn1, 0xffffffff);
	//BnSetUInt64(bn1, 0xffffffff82345678);
	BnSetInt64(bn1, 0x1f3456789);
	BnSetUInt64(bn2, 0x100000000);
	BnAdd(bn3, bn2, bn1);
	//BnDouble(bn1);
	//remainder = BnDivInt(bn1, 3);
	BnPrintLn(bn3);
	BnPrint10Ln(bn3);
	BnMulInt(bn1, 12345);
	BnPrintLn(bn1);
	BnPrint10Ln(bn1);

	BnSetInt64(bn1, 0x12345678);
	BnSetInt64(bn2, 0x12345678);
	BnMul(bn3, bn1, bn2);
	BnMul(bn1, bn3, bn2);
	BnSet(bn2, bn1);
	BnMul(bn3, bn1, bn2);
	BnPrintLn(bn3);
	BnPrint10Ln(bn3);
	printf("bn3=");
	BnAddUInt(bn3, 0xffff1234);
	BnPrintLn(bn3);
	printf("bn1=");
	BnPrintLn(bn1);
	BnDiv(bn2, r, bn3, bn1);
	printf("div=");
	BnPrintLn(bn2);
	BnPrint10Ln(bn2);
	printf("rem=");
	BnPrintLn(r);
	BnPrint10Ln(r);

	count = BnToByteArray(bn3, buffer, sizeof(buffer));
	if (BnToByteArray(bn3, NULL, 0) != count) {
		printf("error BnToByteArray(bn, NULL, 0) get count\n");
	}
	BnSetByteArray(bn2, buffer, count);
	if (BnCmp(bn3, bn2) != 0) {
		printf("error BnToByteArray() or BnSetByteArray()\n");
	}

	BnSetInt64(bn1, -126);
	BnSetInt64(bn2, 5);
	BnDiv(bn3, r, bn1, bn2);
	printf("div=");
	BnPrint10Ln(bn3);

	BnSetInt64(bn1, 10);
	BnSetInt64(bn2, 257);
	GetGCDEx(bn3, m, n, bn1, bn2, 0);
	printf("gcd=");
	BnPrint10Ln(bn3);
	printf("m=");
	BnPrint10Ln(m);
	printf("n=");
	BnPrint10Ln(n);


	BnSetInt64(bn1, 100);
	BnSetInt64(bn2, 17);
	GetGCD(bn3, bn1, bn2);
	printf("gcd=");
	BnPrint10Ln(bn3);

	result = BN_ERR_SUCCESS;
_EXIT:

	BN_SAFEFREE(bn1);
	BN_SAFEFREE(bn2);
	BN_SAFEFREE(bn3);
	BN_SAFEFREE(r);
	BN_SAFEFREE(m);
	BN_SAFEFREE(n);

	return result;
}

int test2()
{
	int result;
	struct MontCtx* ctx = NULL;
	struct BigNumber *bn1 = NULL;
	struct BigNumber *bn2 = NULL;
	struct BigNumber *r = NULL;

	bn1 = BnNew(0);
	bn2 = BnNew(0);
	r = BnNew(1);
	if (bn1 == NULL || bn2 == NULL || r == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	result = BnSetUByteArray(bn2, prime, sizeof(prime));
	if (result != BN_ERR_SUCCESS) {
		printf("BnSetUByteArray error: %d\n", result);
		goto _EXIT;
	}
	//BnSetInt64(bn2, 257);
	result = MontCreate(bn2, &ctx);
	if (result != BN_ERR_SUCCESS) {
		printf("MontCreate error: %d\n", result);
		goto _EXIT;
	}
	BnSetInt64(bn1, 3);
	BnSetInt64(bn2, 15);
	MontExpMod(ctx, r, bn1, bn2);
	printf("3^15=");
	BnPrint10Ln(r);

	result = BN_ERR_SUCCESS;
_EXIT:
	BN_SAFEFREE(bn1);
	BN_SAFEFREE(bn2);
	BN_SAFEFREE(r);
	if (ctx != NULL)
		MontDestroy(ctx);

	return result;
}

int test3()
{
#define TEST3_KEY_BIT		2048
	int result;
	struct BigNumber *bn1 = NULL;
	struct Timer t;
	long elapsed;
	int count = 0;

	bn1 = BnNew(TEST3_KEY_BIT);      // 2048bit      
	if (bn1 == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	printf("Generate Prime Number");
	InitTimer(&t);
	GenPrimeNumberEx(bn1, TEST3_KEY_BIT, primeProgress, &count, NULL);
	printf("\n");
	elapsed = GetElapsedTimeInMillisec(&t);
	BnPrintLn(bn1);
	printf("elapsed   = ");
	PrintTime(elapsed);
	printf("try count = %d\n", count);
	printf("avg time  = %.3lf\n", (double)elapsed / count / 1000);
	printf("\n");

	result = BN_ERR_SUCCESS;
_EXIT:
	BN_SAFEFREE(bn1);
	return result;
}

int test4()
{
#define TEST4_KEY_BIT		4096
	int result;
	struct RSAKeyPair *key = NULL;
	struct BigNumber *m = NULL;
	struct BigNumber *s = NULL;
	struct Timer t;
	uint8_t buffer[TEST4_KEY_BIT / 8 + 1];

	int count;

	m = BnNew(TEST4_KEY_BIT);
	s = BnNew(TEST4_KEY_BIT);
	if (m == NULL || s == NULL) {
		printf("BnNew Error\n");
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	printf("Creating KeyPair...\n");
	InitTimer(&t);
	result = RSACreateKeyPair(TEST4_KEY_BIT, &key);
	PrintElapsed(&t, "RSACreateKeyPair elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("RSACreateKeyPair failed(%d)\n", result);
		goto _EXIT;
	}

	result = BnSetByteArray(m, message, sizeof(message));
	if (result != BN_ERR_SUCCESS) {
		printf("BnSetByteArray failed(%d)\n", result);
		goto _EXIT;
	}

	InitTimer(&t);
	RSASign(key, m, s);
	PrintElapsed(&t, "RSASign elapsed: ");

	printf("secure=\n");
	BnPrintLn(s);

	InitTimer(&t);
	if (RSAVerify(key, s, m) != 0) {
		printf("rsa verify failed\n");
	}
	PrintElapsed(&t, "RSAVerify elapsed: ");

	InitTimer(&t);
	RSAEncrypt(key, m, s);
	PrintElapsed(&t, "RSAEncrypt elapsed: ");

	BnSetUInt(m, 0);

	InitTimer(&t);
	RSADecrypt(key, s, m);
	PrintElapsed(&t, "RSADecrypt elapsed: ");

	count = BnToByteArray(m, buffer, sizeof(buffer));
	buffer[count] = '\0';
	printf("message=%s\n", buffer);

_EXIT:
	BN_SAFEFREE(m);
	BN_SAFEFREE(s);
	if (key != NULL)
		RSADestroyKeyPair(key);

	return result;
}

int test5()
{
#define TEST5_KEY_BIT		2048
	int result;
	struct RSAKeyPair *privkey = NULL;
	struct RSAKeyPair* pubkey = NULL;
	struct BigNumber *m = NULL;
	struct BigNumber* m2 = NULL;
	struct BigNumber *s = NULL;
	struct Timer t;
	uint8_t buffer[2048 / 8 + 1];
	uint8_t *keyData = NULL;
	int count;
	int len;

	m = BnNew(TEST5_KEY_BIT);
	s = BnNew(TEST5_KEY_BIT);
	m2 = BnNew(TEST5_KEY_BIT);
	if (m == NULL || s == NULL || m2 == NULL) {
		printf("BnNew Error\n");
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	result = BnSetByteArray(m, message, sizeof(message));
	if (result != BN_ERR_SUCCESS) {
		printf("BnSetByteArray failed(%d)\n", result);
		goto _EXIT;
	}


	// RSACreateKeyFromByteArray test
	InitTimer(&t);
	result = RSACreateKeyFromByteArray(pub, sizeof(pub), &pubkey);
	PrintElapsed(&t, "RSACreateKeyFromByteArray(pub) elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("RSACreateKeyFromByteArray failed(%d)\n", result);
		goto _EXIT;
	}
	result = RSAVerifyKey(pubkey);
	if (result != BN_ERR_SUCCESS) {
		printf("RSAVerifyKey failed(%d)\n", result);
		goto _EXIT;
	}

	// RSAPubKeyToByteArray test
	result = RSAPubKeyToByteArray(pubkey, NULL, 0, &len);
	if (result != BN_ERR_SUCCESS) {
		printf("RSAPubKeyToByteArray failed(%d)\n", result);
		goto _EXIT;
	}
	if (len != sizeof(pub)) {
		printf("RSAPubKeyToByteArray length error(%d != %d)\n", len, (int)sizeof(pub));
		goto _EXIT;
	}
	keyData = malloc(len);
	if (keyData == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	result = RSAPubKeyToByteArray(pubkey, keyData, len, NULL);
	if (result != BN_ERR_SUCCESS) {
		printf("RSAPubKeyToByteArray failed(%d)\n", result);
		goto _EXIT;
	}
	if (memcmp(keyData, pub, len) != 0) {
		printf("RSAPubKeyToByteArray data error\n");
		goto _EXIT;
	}
	printf("RSACreateKeyFromByteArray check ok\n");
	printf("\n");

	free(keyData);
	keyData = NULL;

	// create private key
	InitTimer(&t);
	result = RSACreateKeyFromByteArray(priv, sizeof(priv), &privkey);
	PrintElapsed(&t, "RSACreateKeyFromByteArray(priv) elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("RSACreateKeyFromByteArray failed(%d)\n", result);
		goto _EXIT;
	}
	result = RSAVerifyKey(privkey);
	if (result != BN_ERR_SUCCESS) {
		printf("RSAVerifyKey failed(%d)\n", result);
		goto _EXIT;
	}

	// RSAPrivKeyToByteArray test
	result = RSAPrivKeyToByteArray(privkey, NULL, 0, &len);
	if (result != BN_ERR_SUCCESS) {
		printf("RSAPrivKeyToByteArray failed(%d)\n", result);
		goto _EXIT;
	}
	if (len != sizeof(priv)) {
		printf("RSAPrivKeyToByteArray length error(%d != %d)\n", len, (int)sizeof(priv));
		goto _EXIT;
	}
	keyData = malloc(len);
	if (keyData == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	result = RSAPrivKeyToByteArray(privkey, keyData, len, NULL);
	if (result != BN_ERR_SUCCESS) {
		printf("RSAPrivKeyToByteArray failed(%d)\n", result);
		goto _EXIT;
	}
	if (memcmp(keyData, priv, len) != 0) {
		printf("RSAPrivKeyToByteArray data error\n");
		goto _EXIT;
	}
	printf("RSACreateKeyFromByteArray check ok\n");
	printf("\n");

	free(keyData);
	keyData = NULL;

	//-------------------------------
	// encrypt and decrypt test
	// encrypt with public key
	InitTimer(&t);
	result = RSAEncrypt(pubkey, m, s);
	PrintElapsed(&t, "RSAEncrypt elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("RSAEncrypt failed(%d)\n", result);
		goto _EXIT;
	}

	printf("secure=\n");
	BnPrintLn(s);

	// decrypt with private key
	InitTimer(&t);
	result = RSADecrypt(privkey, s, m2);
	PrintElapsed(&t, "RSADecrypt elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("RSADecrypt failed(%d)\n", result);
		goto _EXIT;
	}

	if (BnCmp(m, m2) != 0)
	{
		printf("RSADecrypt result is invalid\n");
		printf("original:\n");
		BnPrintLn(m);
		printf("decrypted:\n");
		BnPrintLn(m);
		goto _EXIT;
	}
	printf("RSADecrypt result ok\n");

	count = BnToByteArray(m, buffer, sizeof(buffer));
	buffer[count] = '\0';
	printf("message=%s\n", buffer);

	//----------------------------------------
	// sign and verify test
	// sign with private key
	InitTimer(&t);
	result = RSASign(privkey, m, s);
	PrintElapsed(&t, "RSASign elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("RSADecrypt failed(%d)\n", result);
		goto _EXIT;
	}

	InitTimer(&t);
	result = RSAVerify(pubkey, s, m);
	PrintElapsed(&t, "RSAVerify elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("rsa verify failed\n");
		goto _EXIT;
	}

	BnSetUInt(m, 0);



_EXIT:
	BN_SAFEFREE(m);
	BN_SAFEFREE(s);
	BN_SAFEFREE(m2);
	if (privkey != NULL)
		RSADestroyKeyPair(privkey);
	if (pubkey != NULL)
		RSADestroyKeyPair(pubkey);
	if (keyData != NULL)
		free(keyData);
	return result;
}

int test5_1()
{
#define TEST5_1_KEY_BIT		2048
	int result = BN_ERR_SUCCESS;
	struct RSAKeyPair* privkey = NULL;
	struct RSAKeyPair* pubkey = NULL;
	struct BigNumber* m = NULL;
	struct BigNumber* m2 = NULL;
	struct BigNumber* s = NULL;
	int ntry;
	int mtry;
	int i;
	uint8_t data[TEST5_1_KEY_BIT/8];
	uint8_t data2[TEST5_1_KEY_BIT / 8];
	uint8_t* keydata = NULL;
	int len;

	m = BnNew(TEST5_1_KEY_BIT);
	m2 = BnNew(TEST5_1_KEY_BIT);
	s = BnNew(TEST5_1_KEY_BIT);
	if (m == NULL || s == NULL) {
		printf("BnNew Error\n");
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	printf("rsa encrypt/decrypt test\n");
	for (ntry = 0; ntry < 10; ntry++) {
		printf("try %d - ", ntry);
		fflush(stdout);
		// create key pair
		result = RSACreateKeyPair(TEST5_1_KEY_BIT, &privkey);
		if (result != BN_ERR_SUCCESS) {
			printf("RSACreateKeyPair failed(%d)\n", result);
			goto _EXIT;
		}
		result = RSAPubKeyToByteArray(privkey, NULL, 0, &len);
		if (result != BN_ERR_SUCCESS) {
			printf("RSAPubKeyToByteArray failed(%d)\n", result);
			goto _EXIT;
		}
		keydata = malloc(len);
		if (keydata == NULL) {
			result = BN_ERR_OUT_OF_MEMORY;
			goto _EXIT;
		}
		result = RSAPubKeyToByteArray(privkey, keydata, len, NULL);
		if (result != BN_ERR_SUCCESS) {
			printf("RSAPubKeyToByteArray failed(%d)\n", result);
			goto _EXIT;
		}
		result = RSACreateKeyFromByteArray(keydata, len, &pubkey);
		if (result != BN_ERR_SUCCESS) {
			printf("RSACreateKeyFromByteArray failed(%d)\n", result);
			goto _EXIT;
		}
		result = RSAVerifyKey(pubkey);
		if (result != BN_ERR_SUCCESS) {
			printf("RSAVerifyKey failed(%d)\n", result);
			goto _EXIT;
		}
		free(keydata);
		keydata = NULL;

		for (mtry = 0; mtry < 50; mtry++) {
			// generate random data
			for (i = 0; i < sizeof(data); i++)
				data[i] = rand() % 256;
			// clear msb to make smaller than key
			data[0] &= 0x7f;
			BnSetUByteArray(m, data, sizeof(data));
			// encrypt with public key
			result = RSAEncrypt(pubkey, m, s);
			if (result != BN_ERR_SUCCESS) {
				printf("RSAEncrypt failed(%d)\n", result);
				goto _EXIT;
			}

			// decrypt with private key
			result = RSADecrypt(privkey, s, m2);
			if (result != BN_ERR_SUCCESS) {
				printf("RSADecrypt failed(%d)\n", result);
				goto _EXIT;
			}

			BnToFixedByteArray(m2, data2, sizeof(data2));

			if (memcmp(data, data2, sizeof(data2)) != 0) {
				printf("Decoded data is invalid\n");
				result = BN_ERR_INVALID_DATA;
				goto _EXIT;
			}

			// sign with private key
			result = RSASign(privkey, m, s);
			if (result != BN_ERR_SUCCESS) {
				printf("RSASign failed(%d)\n", result);
				goto _EXIT;
			}

			// verify with public key
			result = RSAVerify(pubkey, s, m2);
			if (result != BN_ERR_SUCCESS) {
				printf("RSAVerify failed(%d)\n", result);
				goto _EXIT;
			}
			printf("."); fflush(stdout);
		}
		RSADestroyKeyPair(privkey);
		privkey = NULL;
		RSADestroyKeyPair(pubkey);
		pubkey = NULL;
		printf("\n");
	}
	printf(" - ok\n");


_EXIT:
	BN_SAFEFREE(m);
	BN_SAFEFREE(m2);
	BN_SAFEFREE(s);
	if (keydata != NULL)
		free(keydata);
	if (privkey != NULL)
		RSADestroyKeyPair(privkey);
	if (pubkey != NULL)
		RSADestroyKeyPair(pubkey);
	return result;
}

static void printHex(char* prefix, uint8_t* data, int len)
{
	printf("%s", prefix);
	while (len-- > 0) {
		printf("%02x", *data++);
	}
	printf("\n");
}

/*
static void printHexData( char* prefix, uint8_t* data, int len )
{
	int i;
	printf( "%s", prefix );

	for ( i = 0; i < len; i++ ) {
		printf( "0x%02x", *data++ );
		if ( i != len - 1 )
		{
			if ( ( i % 16 ) == 15 )
			{
				printf( ",\n" );
			}
			else
			{
				printf( ", " );
			}
		}
	}
	printf( "\n" );
}
*/

// sha1
static uint8_t message1[] = "The quick brown fox jumps over the lazy dog";
static uint8_t md2_1[16] = { 0x03, 0xd8, 0x5a, 0x0d, 0x62, 0x9d, 0x2c, 0x44, 0x2e, 0x98, 0x75, 0x25, 0x31, 0x9f, 0xc4, 0x71 };
static uint8_t md4_1[16] = { 0x1b, 0xee, 0x69, 0xa4, 0x6b, 0xa8, 0x11, 0x18, 0x5c, 0x19, 0x47, 0x62, 0xab, 0xae, 0xae, 0x90 };
static uint8_t md5_1[16] = { 0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6 };
static uint8_t sha1_1[20] = { 0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12 };
static uint8_t sha224_1[28] = { 0x73, 0x0e, 0x10, 0x9b, 0xd7, 0xa8, 0xa3, 0x2b, 0x1c, 0xb9, 0xd9, 0xa0, 0x9a, 0xa2, 0x32, 0x5d, 0x24, 0x30, 0x58, 0x7d, 0xdb, 0xc0, 0xc3, 0x8b, 0xad, 0x91, 0x15, 0x25 };
static uint8_t sha256_1[32] = { 0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92 };
static uint8_t sha384_1[48] = { 0xca, 0x73, 0x7f, 0x10, 0x14, 0xa4, 0x8f, 0x4c, 0x0b, 0x6d, 0xd4, 0x3c, 0xb1, 0x77, 0xb0, 0xaf, 0xd9, 0xe5, 0x16, 0x93, 0x67, 0x54, 0x4c, 0x49, 0x40, 0x11, 0xe3, 0x31, 0x7d, 0xbf, 0x9a, 0x50, 0x9c, 0xb1, 0xe5, 0xdc, 0x1e, 0x85, 0xa9, 0x41, 0xbb, 0xee, 0x3d, 0x7f, 0x2a, 0xfb, 0xc9, 0xb1 };
static uint8_t sha512_1[64] = { 0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73, 0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e, 0xd7, 0x69, 0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88, 0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64, 0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39, 0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6, 0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f, 0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6 };
static uint8_t sha512_224_1[28] = { 0x94, 0x4c, 0xd2, 0x84, 0x7f, 0xb5, 0x45, 0x58, 0xd4, 0x77, 0x5d, 0xb0, 0x48, 0x5a, 0x50, 0x00, 0x31, 0x11, 0xc8, 0xe5, 0xda, 0xa6, 0x3f, 0xe7, 0x22, 0xc6, 0xaa, 0x37 };
static uint8_t sha512_256_1[32] = { 0xdd, 0x9d, 0x67, 0xb3, 0x71, 0x51, 0x9c, 0x33, 0x9e, 0xd8, 0xdb, 0xd2, 0x5a, 0xf9, 0x0e, 0x97, 0x6a, 0x1e, 0xee, 0xfd, 0x4a, 0xd3, 0xd8, 0x89, 0x00, 0x5e, 0x53, 0x2f, 0xc5, 0xbe, 0xf0, 0x4d };
static uint8_t has160_1[20] = { 0xab, 0xe2, 0xb8, 0xc7, 0x11, 0xf9, 0xe8, 0x57, 0x9a, 0xa8, 0xeb, 0x40, 0x75, 0x7a, 0x27, 0xb4, 0xef, 0x14, 0xa7, 0xea };

static uint8_t message2[] = "The quick brown fox jumps over the lazy dog............................................................................";
static uint8_t md2_2[16] = { 0x5d, 0xc7, 0xe4, 0x90, 0xea, 0x58, 0x37, 0x02, 0xe3, 0x90, 0x50, 0xcf, 0x65, 0x7d, 0xa7, 0x91 };
static uint8_t md4_2[16] = { 0xf3, 0x6f, 0x13, 0xf7, 0x9a, 0x9f, 0x86, 0xf8, 0x9b, 0xcc, 0x4b, 0x63, 0xb9, 0x25, 0xf5, 0x30 };
static uint8_t md5_2[16] = { 0xed, 0x6f, 0x47, 0xb8, 0x75, 0xf6, 0x1a, 0xff, 0xfd, 0x53, 0x21, 0x30, 0x73, 0x4e, 0x82, 0x74 };
static uint8_t sha1_2[20] = { 0x0b, 0xeb, 0x95, 0xb4, 0x89, 0x0c, 0xf5, 0xe1, 0x7e, 0x0e, 0x55, 0x4b, 0x91, 0x57, 0xd0, 0xf7, 0xc0, 0x24, 0xc8, 0x9a };
static uint8_t sha224_2[28] = { 0x70, 0x59, 0x1d, 0xe4, 0x9b, 0x35, 0x02, 0x93, 0x76, 0x01, 0x08, 0xbe, 0xe4, 0x8e, 0x1d, 0xac, 0x99, 0x37, 0x37, 0x1c, 0x1d, 0xaa, 0x23, 0x5c, 0x24, 0xf9, 0x5a, 0xd4 };
static uint8_t sha256_2[32] = { 0x05, 0x26, 0xcf, 0x39, 0xb5, 0x1c, 0x82, 0x0c, 0xcb, 0x40, 0xf3, 0xe3, 0x39, 0x29, 0x4f, 0x0e, 0x8a, 0x99, 0xd0, 0x60, 0xc5, 0xa2, 0xe0, 0x18, 0x96, 0xc9, 0x9b, 0xaa, 0xb8, 0x69, 0x47, 0xf5 };
static uint8_t sha384_2[48] = { 0xd9, 0x77, 0x1d, 0x52, 0x9e, 0xdd, 0xa5, 0x03, 0xab, 0xe4, 0xc3, 0xa3, 0xe1, 0x52, 0xd9, 0x71, 0xf8, 0xf9, 0xfd, 0xf8, 0xd7, 0x5d, 0x0f, 0xd6, 0xe3, 0xea, 0xdf, 0x60, 0xa9, 0xa0, 0x76, 0x64, 0x65, 0xf2, 0xdf, 0xf4, 0x7a, 0xa8, 0x7f, 0x98, 0x01, 0x1a, 0x82, 0xbc, 0x00, 0xf7, 0x53, 0xb4 };
static uint8_t sha512_2[64] = { 0xc6, 0xa9, 0xc9, 0xfc, 0xe3, 0x69, 0x6b, 0xe6, 0x25, 0x12, 0xb9, 0x0e, 0x4d, 0xbc, 0xd8, 0xa9, 0x65, 0x74, 0x15, 0x42, 0x15, 0x7f, 0xf1, 0xf6, 0x55, 0xba, 0x6a, 0x4a, 0x96, 0xdb, 0xc4, 0x68, 0xde, 0x38, 0x6f, 0xaf, 0x24, 0xa5, 0xf9, 0xee, 0x0b, 0x3d, 0x5e, 0x26, 0x8b, 0x68, 0x6d, 0x0e, 0x36, 0xbc, 0x94, 0xe9, 0x68, 0xde, 0x8e, 0xdd, 0x99, 0x87, 0xad, 0xc8, 0x1e, 0xe1, 0xaa, 0x8c };
static uint8_t sha512_224_2[28] = { 0x82, 0xbf, 0x5b, 0x59, 0xcc, 0x9e, 0xa5, 0x48, 0x04, 0x23, 0xf4, 0xcf, 0xdc, 0x97, 0xc9, 0x05, 0x2e, 0x9e, 0x49, 0x4b, 0xd1, 0xd1, 0xa8, 0x9d, 0xd1, 0xf1, 0xe6, 0x8b };
static uint8_t sha512_256_2[32] = { 0x36, 0x21, 0xdb, 0xe4, 0x57, 0x99, 0x15, 0xb5, 0xe7, 0x95, 0xac, 0x51, 0x5e, 0xb1, 0x52, 0xdb, 0xa6, 0xb9, 0xba, 0x2f, 0xfb, 0x17, 0xc2, 0x59, 0x08, 0x8c, 0xaf, 0x5c, 0x8d, 0x00, 0x38, 0xa5 };
static uint8_t has160_2[20] = { 0x84, 0x5b, 0x19, 0x7a, 0x70, 0xef, 0x0e, 0x9e, 0xbd, 0x8e, 0xa9, 0x07, 0x55, 0x6e, 0x74, 0xa2, 0x49, 0x41, 0x18, 0x8c };



// digest
int test6()
{
	int result = BN_ERR_SUCCESS;
	struct RaSha2Ctx ctx;
	uint8_t digest[64];

	printf("\n");
	printf("test sha2\n");
	printf("message1 = %s\n", message1);

	RaMd2(message1, sizeof(message1) - 1, digest);
	printHex("md2(message1) = ", digest, sizeof(md2_1));
	if (memcmp(digest, md2_1, sizeof(md2_1)) != 0) {
		printf("md2(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaMd4(message1, sizeof(message1) - 1, digest);
	printHex("md4(message1) = ", digest, sizeof(md4_1));
	if (memcmp(digest, md4_1, sizeof(md4_1)) != 0) {
		printf("md4(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaMd5(message1, sizeof(message1) - 1, digest);
	printHex("md5(message1) = ", digest, sizeof(md5_1));
	if (memcmp(digest, md5_1, sizeof(md5_1)) != 0) {
		printf("md5(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha1(message1, sizeof(message1) - 1, digest);
	printHex("sha1(message1) = ", digest, sizeof(sha1_1));
	if (memcmp(digest, sha1_1, sizeof(sha1_1)) != 0) {
		printf("sha1(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha256(message1, sizeof(message1) - 1, digest);
	printHex("sha-256(message1) = ", digest, sizeof(sha256_1));
	if (memcmp(digest, sha256_1, sizeof(sha256_1)) != 0) {
		printf("sha-256(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_512);
	RaSha2Update(&ctx, message1, sizeof(message1) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-512(message1) = ", digest, sizeof(sha512_1));
	if (memcmp(digest, sha512_1, sizeof(sha512_1)) != 0) {
		printf("sha-512(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_224);
	RaSha2Update(&ctx, message1, sizeof(message1) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-224(message1) = ", digest, sizeof(sha224_1));
	if (memcmp(digest, sha224_1, sizeof(sha224_1)) != 0) {
		printf("sha-224(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_384);
	RaSha2Update(&ctx, message1, sizeof(message1) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-384(message1) = ", digest, sizeof(sha384_1));
	if (memcmp(digest, sha384_1, sizeof(sha384_1)) != 0) {
		printf("sha-384(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_512_224);
	RaSha2Update(&ctx, message1, sizeof(message1) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-512/224(message1) = ", digest, sizeof(sha512_224_1));
	if (memcmp(digest, sha512_224_1, sizeof(sha512_224_1)) != 0) {
		printf("sha-512/224(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_512_256);
	RaSha2Update(&ctx, message1, sizeof(message1) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-512/256(message1) = ", digest, sizeof(sha512_256_1));
	if (memcmp(digest, sha512_256_1, sizeof(sha512_256_1)) != 0) {
		printf("sha-512/256(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaHas160(message1, sizeof(message1) - 1, digest);
	printHex("has-160(message1) = ", digest, sizeof(has160_1));
	if (memcmp(digest, has160_1, sizeof(has160_1)) != 0) {
		printf("has-160(message1) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	printf("\n");
	printf("message2 = %s\n", message2);

	RaMd2(message2, sizeof(message2) - 1, digest);
	printHex("md2(message2) = ", digest, sizeof(md2_2));
	if (memcmp(digest, md2_2, sizeof(md2_2)) != 0) {
		printf("md2(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaMd4(message2, sizeof(message2) - 1, digest);
	printHex("md4(message2) = ", digest, sizeof(md4_2));
	if (memcmp(digest, md4_2, sizeof(md4_2)) != 0) {
		printf("md4(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaMd5(message2, sizeof(message2) - 1, digest);
	printHex("md5(message2) = ", digest, sizeof(md5_2));
	if (memcmp(digest, md5_2, sizeof(md5_2)) != 0) {
		printf("md5(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha1(message2, sizeof(message2) - 1, digest);
	printHex("sha1(message2) = ", digest, sizeof(sha1_2));
	if (memcmp(digest, sha1_2, sizeof(sha1_2)) != 0) {
		printf("sha1(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha256(message2, sizeof(message2) - 1, digest);
	printHex("sha-256(message2) = ", digest, sizeof(sha256_2));
	if (memcmp(digest, sha256_2, sizeof(sha256_2)) != 0) {
		printf("sha-256(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_512);
	RaSha2Update(&ctx, message2, sizeof(message2) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-512(message2) = ", digest, sizeof(sha512_2));
	if (memcmp(digest, sha512_2, sizeof(sha512_2)) != 0) {
		printf("sha-512(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_224);
	RaSha2Update(&ctx, message2, sizeof(message2) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-224(message2) = ", digest, sizeof(sha224_2));
	if (memcmp(digest, sha224_2, sizeof(sha224_2)) != 0) {
		printf("sha-224(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_384);
	RaSha2Update(&ctx, message2, sizeof(message2) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-384(message2) = ", digest, sizeof(sha384_2));
	if (memcmp(digest, sha384_2, sizeof(sha384_2)) != 0) {
		printf("sha-384(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_512_224);
	RaSha2Update(&ctx, message2, sizeof(message2) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-512/224(message2) = ", digest, sizeof(sha512_224_2));
	if (memcmp(digest, sha512_224_2, sizeof(sha512_224_2)) != 0) {
		printf("sha-512/224(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaSha2Init(&ctx, RA_DGST_SHA2_512_256);
	RaSha2Update(&ctx, message2, sizeof(message2) - 1);
	RaSha2Final(&ctx, digest);
	printHex("sha-512/256(message2) = ", digest, sizeof(sha512_256_2));
	if (memcmp(digest, sha512_256_2, sizeof(sha512_256_2)) != 0) {
		printf("sha-512/256(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	RaHas160(message2, sizeof(message2) - 1, digest);
	printHex("has-160(message2) = ", digest, sizeof(has160_2));
	if (memcmp(digest, has160_2, sizeof(has160_2)) != 0) {
		printf("has-160(message2) failed\n");
		result = BN_ERR_INVALID_DATA;
	}

	return result;
}

static uint8_t aes128_ecb1[] = {
	0xdc, 0xd3, 0x09, 0x6e, 0x63, 0x6c, 0x77, 0x85, 0xa4, 0x27, 0x21, 0x84, 0x67, 0x47, 0xd1, 0xc3,
	0x76, 0xbc, 0x10, 0x16, 0xc5, 0xfa, 0x0e, 0x33, 0x82, 0x3e, 0xe4, 0x82, 0x3b, 0xb6, 0x0f, 0x45,
	0x29, 0xf5, 0xcb, 0xf2, 0x20, 0xad, 0x17, 0x9a, 0x71, 0x6b, 0x24, 0x3a, 0x56, 0xcd, 0x50, 0x0b };
static uint8_t aes128_cbc1[] = {
	0xdc, 0xd3, 0x09, 0x6e, 0x63, 0x6c, 0x77, 0x85, 0xa4, 0x27, 0x21, 0x84, 0x67, 0x47, 0xd1, 0xc3,
	0x23, 0x49, 0xbe, 0x98, 0x99, 0x3a, 0x01, 0x0c, 0x7c, 0xe1, 0xb9, 0xa9, 0xbc, 0x35, 0x0b, 0x31,
	0xb5, 0x1f, 0xb2, 0xe6, 0x06, 0xd0, 0xf4, 0xc2, 0x55, 0xd7, 0xda, 0xdf, 0x6d, 0xbe, 0xdf, 0x65 };
static uint8_t aes128_cfb1[] = {
	0x32, 0x81, 0x2e, 0xf4, 0x9e, 0xff, 0x45, 0x58, 0xe3, 0x6c, 0x98, 0x2b, 0xa5, 0x43, 0x45, 0x0e,
	0x08, 0xcd, 0xe2, 0xb6, 0xd8, 0x98, 0x6f, 0x11, 0xcd, 0xe5, 0x79, 0xd4, 0x29, 0x4f, 0x52, 0x30,
	0xce, 0x6f, 0x2e, 0x2c, 0xa1, 0xaa, 0xf0, 0xa6, 0x16, 0x78, 0x84, 0x4f, 0x91, 0x87, 0xda, 0x03 };
static uint8_t aes128_ofb1[] = {
	0x32, 0x81, 0x2e, 0xf4, 0x9e, 0xff, 0x45, 0x58, 0xe3, 0x6c, 0x98, 0x2b, 0xa5, 0x43, 0x45, 0x0e,
	0x91, 0xfa, 0xc5, 0x6a, 0x38, 0x97, 0xf3, 0xa7, 0x60, 0xf3, 0x7c, 0x8c, 0x45, 0x9b, 0xad, 0xc8,
	0xc9, 0x69, 0xd6, 0x01, 0x6e, 0xa7, 0x8a, 0x60, 0x37, 0x1f, 0xd3, 0xbf, 0x89, 0xf1, 0xbb, 0xb7 };
// aes
int test7()
{
	int result = BN_ERR_SUCCESS;
#define TEST7_BLOCK_SIZE		4096
	struct RaAesCtx ctx;
	uint8_t key[32];
	uint8_t input[10240];
	int inputLen;
	uint8_t encrypted[TEST7_BLOCK_SIZE];
	uint8_t decrypted[TEST7_BLOCK_SIZE];
	uint8_t iv[16];
	int readLen;
	int writtenLen;
	int i;
	int leftLen;
	int srcOffset;
	int destOffset;
	int ntry;
	struct Timer t;

	memset(iv, 0, 16);

	/* fixed data encryption/decryption test */
	memset( key, 0, sizeof( key ) );

	memcpy( input, message1, sizeof( message1 ) );
	inputLen = sizeof(message1);
	memset( decrypted, 0, sizeof( decrypted ) );
	RaAesInit( &ctx, key, RA_AES_128, RA_AES_MODE_ECB );
	writtenLen = RaAesEncryptFinal( &ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7 );
	printHex( "AES/128/ECB = ", encrypted, writtenLen );
	if ( writtenLen != sizeof( aes128_ecb1 ) || memcmp( encrypted, aes128_ecb1, writtenLen ) ) {
		printf( "AES/128/ECB encrypt failed\n" );
		result = BN_ERR_INVALID_DATA;
	}
	writtenLen = RaAesDecryptFinal( &ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7 );
	if ( inputLen != writtenLen || memcmp( input, decrypted, writtenLen ) != 0 ) {
		printf( "AES/128/ECB decrypt failed\n" );
		result = BN_ERR_INVALID_DATA;
	}

	RaAesInit( &ctx, key, RA_AES_128, RA_AES_MODE_CBC );
	writtenLen = RaAesEncryptFinal( &ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7 );
	printHex( "AES/128/CBC = ", encrypted, writtenLen );
	if ( writtenLen != sizeof( aes128_cbc1 ) || memcmp( encrypted, aes128_cbc1, writtenLen ) ) {
		printf( "AES/128/ECB encrypt failed\n" );
		result = BN_ERR_INVALID_DATA;
	}
	RaAesSetIV( &ctx, iv );
	writtenLen = RaAesDecryptFinal( &ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7 );
	if ( inputLen != writtenLen || memcmp( input, decrypted, writtenLen ) != 0 ) {
		printf( "AES/128/CBC decrypt failed\n" );
		result = BN_ERR_INVALID_DATA;
	}

	RaAesInit( &ctx, key, RA_AES_128, RA_AES_MODE_CFB);
	writtenLen = RaAesEncryptFinal( &ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7 );
	printHex( "AES/128/CFB = ", encrypted, writtenLen );
	if ( writtenLen != sizeof( aes128_cfb1 ) || memcmp( encrypted, aes128_cfb1, writtenLen ) ) {
		printf( "AES/128/CFB encrypt failed\n" );
		result = BN_ERR_INVALID_DATA;
	}
	RaAesSetIV( &ctx, iv );
	writtenLen = RaAesDecryptFinal( &ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7 );
	if ( inputLen != writtenLen || memcmp( input, decrypted, writtenLen ) != 0 ) {
		printf( "AES/128/CFB decrypt failed\n" );
		result = BN_ERR_INVALID_DATA;
	}

	RaAesInit( &ctx, key, RA_AES_128, RA_AES_MODE_OFB );
	writtenLen = RaAesEncryptFinal( &ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7 );
	printHex( "AES/128/OFB = ", encrypted, writtenLen );
	if ( writtenLen != sizeof( aes128_ofb1 ) || memcmp( encrypted, aes128_ofb1, writtenLen ) ) {
		printf( "AES/128/OFB encrypt failed\n" );
		result = BN_ERR_INVALID_DATA;
	}
	RaAesSetIV( &ctx, iv );
	writtenLen = RaAesDecryptFinal( &ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7 );
	if ( inputLen != writtenLen || memcmp( input, decrypted, writtenLen ) != 0 ) {
		printf( "AES/128/OFB decrypt failed\n" );
		result = BN_ERR_INVALID_DATA;
	}
	if (result != BN_ERR_SUCCESS) {
		goto _EXIT;
	}

	printf("random data encryption/decryption test\n");
	for (ntry = 0; ntry < 20000 && result == BN_ERR_SUCCESS; ntry++)
	{
		/* random data encryption/decryption test */
		for (i = 0; i < 32; i++) {
			key[i] = rand() % 256;
		}
		inputLen = (rand() % TEST7_BLOCK_SIZE-256) + 256;	// 256~4096
		for (i = 0; i < inputLen; i++) {
			input[i] = rand() % 256;
		}

		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_128, RA_AES_MODE_ECB);
		writtenLen = RaAesEncryptFinal(&ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7);
		writtenLen = RaAesDecryptFinal(&ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7);
		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/128/ECB failed\n");
			result = BN_ERR_INVALID_DATA;
		}

		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_128, RA_AES_MODE_CBC);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesEncryptFinal(&ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesDecryptFinal(&ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7);
		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/128/CBC failed\n");
			result = BN_ERR_INVALID_DATA;
		}

		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_192, RA_AES_MODE_ECB);
		writtenLen = RaAesEncryptFinal(&ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7);
		writtenLen = RaAesDecryptFinal(&ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7);
		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/192/ECB failed\n");
			result = BN_ERR_INVALID_DATA;
		}

		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_192, RA_AES_MODE_CBC);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesEncryptFinal(&ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesDecryptFinal(&ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7);
		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/192/CBC failed\n");
			result = BN_ERR_INVALID_DATA;
		}

		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_256, RA_AES_MODE_ECB);
		writtenLen = RaAesEncryptFinal(&ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7);
		writtenLen = RaAesDecryptFinal(&ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7);
		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/256/ECB failed\n");
			result = BN_ERR_INVALID_DATA;
		}

		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_256, RA_AES_MODE_CBC);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesEncryptFinal(&ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesDecryptFinal(&ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7);
		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/256/CBC failed\n");
			result = BN_ERR_INVALID_DATA;
		}

		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_128, RA_AES_MODE_CFB);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesEncryptFinal(&ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesDecryptFinal(&ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7);
		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/128/CFB failed\n");
			result = BN_ERR_INVALID_DATA;
		}

		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_128, RA_AES_MODE_OFB);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesEncryptFinal(&ctx, input, inputLen, encrypted, RA_AES_PADDING_PKCS7);
		RaAesSetIV(&ctx, iv);
		writtenLen = RaAesDecryptFinal(&ctx, encrypted, writtenLen, decrypted, RA_AES_PADDING_PKCS7);
		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/128/OFB failed\n");
			result = BN_ERR_INVALID_DATA;
		}

		// encrypt continus data
		//printf("encrypt continus data\n");
		memset(decrypted, 0, sizeof(decrypted));
		RaAesInit(&ctx, key, RA_AES_128, RA_AES_MODE_CBC);
		RaAesSetIV(&ctx, iv);
		leftLen = inputLen;
		srcOffset = 0;
		destOffset = 0;
		while (leftLen > 0) {
			readLen = (rand() % 100) + 1;
			if (readLen > leftLen)
				readLen = leftLen;
			writtenLen = RaAesEncrypt(&ctx, input + srcOffset, readLen, encrypted + destOffset);
			srcOffset += readLen;
			destOffset += writtenLen;
			leftLen -= readLen;
		}
		writtenLen = RaAesEncryptFinal(&ctx, NULL, 0, encrypted + destOffset, RA_AES_PADDING_PKCS7);
		destOffset += writtenLen;

		// decrypt continus data
		RaAesSetIV(&ctx, iv);
		leftLen = destOffset;
		srcOffset = 0;
		destOffset = 0;

		// padding size can be up to 16 bytes.
		while (leftLen > 16) {
			readLen = (rand() % 50) + 1;
			if (readLen > leftLen - 16)
				break;
			readLen = (rand() % readLen) + 1;
			writtenLen = RaAesDecrypt(&ctx, encrypted + srcOffset, readLen, decrypted + destOffset);
			srcOffset += readLen;
			destOffset += writtenLen;
			leftLen -= readLen;
		}
		writtenLen = RaAesDecryptFinal(&ctx, encrypted + srcOffset, leftLen, decrypted + destOffset, RA_AES_PADDING_PKCS7);
		destOffset += writtenLen;

		writtenLen = destOffset;

		if (inputLen != writtenLen || memcmp(input, decrypted, writtenLen) != 0) {
			printf("AES/128/CBC continus crypt failed\n");
			result = BN_ERR_INVALID_DATA;
		}
		if ((ntry % 1000) == 0) {
			printf("."); fflush(stdout);
		}
	}
	if (result == BN_ERR_SUCCESS) {
		printf(" - ok\n");
	}
	else {
		printf(" - failed\n");
		goto _EXIT;
	}

	// performance test
	memset( decrypted, 0, sizeof( decrypted ) );
	InitTimer( &t );
	for (i = 0; i < 102400; i++) {
		RaAesInit(&ctx, key, RA_AES_128, RA_AES_MODE_CBC);
	}
	PrintElapsed( &t, "AES/128/CBC Init * 100k times elapsed: " );

	inputLen = sizeof(input);
	memset( input, 0, inputLen );

	RaAesSetIV( &ctx, iv );
	InitTimer( &t );
	for (i = 0; i < 102400; i++) {
		writtenLen = RaAesEncrypt(&ctx, input, inputLen, input);
		if ((i % 10240) == 10239) {
			printf("."); fflush(stdout);
		}
	}
	printf("\n");
	PrintElapsed( &t, "AES/128/CBC Encrypt 1GB elapsed: " );

	RaAesSetIV( &ctx, iv );
	InitTimer( &t );
	for (i = 0; i < 102400; i++) {
		RaAesDecrypt(&ctx, input, writtenLen, input);
		if ((i % 10240) == 0) {
			printf("."); fflush(stdout);
		}
	}
	printf("\n");
	PrintElapsed( &t, "AES/128/CBC Decrypt 1GB elapsed: " );

	if (result == BN_ERR_SUCCESS) {
		printf("AES test ok\n");
	}
_EXIT:
	return result;
}


int main()
{
	int result;
	srand((unsigned)time(0));

	printf("\n--------------------------------\n");
	printf("test1 start\n");
	result = test1();
	if (result != BN_ERR_SUCCESS) {
		printf("test1 error: %d\n", result);
		goto _EXIT;
	}

	printf("\n--------------------------------\n");
	printf("test2 start\n");
	result = test2();
	if (result != BN_ERR_SUCCESS) {
		printf("test2 error: %d\n", result);
		goto _EXIT;
	}

	printf("\n--------------------------------\n");
	printf("test3 start\n");
	result = test3();
	if (result != BN_ERR_SUCCESS) {
		printf("test3 error: %d\n", result);
		goto _EXIT;
	}

	printf("\n--------------------------------\n");
	printf("test4 start\n");
	result = test4();
	if (result != BN_ERR_SUCCESS) {
		printf("test4 error: %d\n", result);
		goto _EXIT;
	}

	printf("\n--------------------------------\n");
	printf("test5 start\n");
	result = test5();
	if (result != BN_ERR_SUCCESS) {
		printf("test5 error: %d\n", result);
		goto _EXIT;
	}

	result = test5_1();
	if (result != BN_ERR_SUCCESS) {
		printf("test5_1 error: %d\n", result);
		goto _EXIT;
	}

	printf("\n--------------------------------\n");
	printf("test6 start\n");
	result = test6();
	if (result != BN_ERR_SUCCESS) {
		printf("test6 error: %d\n", result);
		goto _EXIT;
	}

	printf("\n--------------------------------\n");
	printf("test7 start\n");
	result = test7();
	if (result != BN_ERR_SUCCESS) {
		printf("test7 error: %d\n", result);
		goto _EXIT;
	}


	printf("\n");

_EXIT:

	return 0;
}

