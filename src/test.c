/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "bignumber.h"
#include "gcd.h"
#include "montexpmod.h"
#include "prime.h"
#include "rsa.h"
#include "asn1.h"

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

static void PrintElapsed(struct Timer *t, char* message)
{
	long elapsed = GetElapsedTimeInMillisec(t);
	printf("%s", message);
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

	BnSetInt64(bn1, -1);

	count = BnToByteArray(bn1, buffer, sizeof(buffer));
	if (BnToByteArray(bn1, NULL, 0) != count) {
		printf("error BnToByteArray(bn, NULL, 0) get count\n");
	}
	BnSetByteArray(bn2, buffer, count);
	if (BnCmp(bn1, bn2) != 0) {
		printf("error BnToByteArray() or BnSetByteArray()\n");
	}

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
	int result;
	struct BigNumber *bn1 = NULL;
	struct Timer t;
	long elapsed;
	int count = 0;

	bn1 = BnNew(2048);      // 2048bit      
	if (bn1 == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	printf("Generate Prime Number");
	InitTimer(&t);
	GenPrimeNumberEx(bn1, 2048, primeProgress, &count, NULL);
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
	int result;
	struct RSAKeyPair *key = NULL;
	struct BigNumber *m = NULL;
	struct BigNumber *s = NULL;
	struct Timer t;
	uint8_t buffer[2048 / 8 + 1];

	int count;

	m = BnNew(2048);
	s = BnNew(2048);
	if (m == NULL || s == NULL) {
		printf("BnNew Error\n");
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	InitTimer(&t);
	result = RSACreateKeyPair(2048, &key);
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
	RSAEncrypt(key, m, s);
	PrintElapsed(&t, "RSAEncrypt elapsed: ");

	printf("secure=\n");
	BnPrintLn(s);

	InitTimer(&t);
	if (RSAVerify(key, s, m) != 0) {
		printf("rsa verify failed\n");
	}
	PrintElapsed(&t, "RSAVerify elapsed: ");

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
	int result;
	struct RSAKeyPair *key = NULL;
	struct BigNumber *m = NULL;
	struct BigNumber *s = NULL;
	struct Timer t;
	uint8_t buffer[2048 / 8 + 1];
	uint8_t *keyData = NULL;
	int count;
	int len;

	m = BnNew(2048);
	s = BnNew(2048);
	if (m == NULL || s == NULL) {
		printf("BnNew Error\n");
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}

	InitTimer(&t);
	result = RSACreateKeyFromByteArray(pub, sizeof(pub), &key);
	PrintElapsed(&t, "RSACreateKeyFromByteArray(pub) elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("RSACreateKeyFromByteArray failed(%d)\n", result);
		goto _EXIT;
	}

	result = BnSetByteArray(m, message, sizeof(message));
	if (result != BN_ERR_SUCCESS) {
		printf("BnSetByteArray failed(%d)\n", result);
		goto _EXIT;
	}

	InitTimer(&t);
	RSAEncrypt(key, m, s);
	PrintElapsed(&t, "RSAEncrypt elapsed: ");

	printf("secure=\n");
	BnPrintLn(s);

	// RSAPubKeyToByteArray test
	result = RSAPubKeyToByteArray(key, NULL, 0, &len);
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
	result = RSAPubKeyToByteArray(key, keyData, len, NULL);
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

	RSADestroyKeyPair(key);
	key = NULL;

	InitTimer(&t);
	result = RSACreateKeyFromByteArray(priv, sizeof(priv), &key);
	PrintElapsed(&t, "RSACreateKeyFromByteArray(priv) elapsed: ");
	if (result != BN_ERR_SUCCESS) {
		printf("RSACreateKeyFromByteArray failed(%d)\n", result);
		goto _EXIT;
	}

	InitTimer(&t);
	if (RSAVerify(key, s, m) != 0) {
		printf("rsa verify failed\n");
	}
	PrintElapsed(&t, "RSAVerify elapsed: ");

	BnSetUInt(m, 0);

	InitTimer(&t);
	RSADecrypt(key, s, m);
	PrintElapsed(&t, "RSADecrypt elapsed: ");

	count = BnToByteArray(m, buffer, sizeof(buffer));
	buffer[count] = '\0';
	printf("message=%s\n", buffer);

	// RSAPubKeyToByteArray test
	result = RSAPrivKeyToByteArray(key, NULL, 0, &len);
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
	result = RSAPrivKeyToByteArray(key, keyData, len, NULL);
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


_EXIT:
	BN_SAFEFREE(m);
	BN_SAFEFREE(s);
	if (key != NULL)
		RSADestroyKeyPair(key);

	return result;
}


int main()
{
	int result;

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

	printf("\n");


_EXIT:

	return 0;
}
