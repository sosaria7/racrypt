/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RACRYPT_H__
#define __RACRYPT_H__

#define RACRYPT_DIGEST_UNROLL
//#define RACRYPT_AES_MIN_TABLE
//#define RACRYPT_PRIME_MIN_TABLE
//#define RACRYPT_RSA_VERIFY_KEY
//#define HAVE_TIMES
#define HAVE_STDINT

#ifdef HAVE_STDINT
#include <stdint.h>
#else
//typedef char				int8_t;
typedef unsigned char		uint8_t;
typedef          short		int16_t;
typedef unsigned short		uint16_t;
typedef          int		int32_t;
typedef unsigned int		uint32_t;
//typedef          long long	int64_t;
//typedef unsigned long long	uint64_t;
typedef          long		int64_t;
typedef unsigned long		uint64_t;
typedef          long		intptr_t;
typedef unsigned long		uintptr_t;
#define UINT64_C(v)			v##L
#endif

#include "racrypt_com.h"
#include "racrypt_bn.h"
#include "racrypt_pk.h"
#include "racrypt_digest.h"
#include "racrypt_cipher.h"

#endif

