/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __RACRYPT_H__
#define __RACRYPT_H__

#define RACRYPT_DIGEST_UNROLL
//#define RACRYPT_AES_MIN_TABLE
//#define RACRYPT_PRIME_MIN_TABLE
//#define RACRYPT_RSA_VERIFY_KEY
//#define BN_WORD_BYTE	4

#if defined RACRYPT_USE_ASM_X86
#define RACRYPT_USE_ASM_SHA1_X86
#define RACRYPT_USE_ASM_SHA256_X86
#define RACRYPT_USE_ASM_AES_X86
#endif


//#define WORDS_BIGENDIAN
//#define HAVE_TIMES
#define HAVE_STDINT_H
#define HAVE_LIMITS_H

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
//typedef char				int8_t;
typedef unsigned char		uint8_t;
typedef          short		int16_t;
typedef unsigned short		uint16_t;
typedef          int		int32_t;
typedef unsigned int		uint32_t;
typedef          long		intptr_t;
typedef unsigned long		uintptr_t;
//typedef          long long	int64_t;
//typedef unsigned long long	uint64_t;
//#define UINT64_C(v)			v##LL
typedef          long		int64_t;
typedef unsigned long		uint64_t;
#define UINT64_C(v)			v##L
#endif

#include "racrypt_com.h"
#include "racrypt_bn.h"
#include "racrypt_pk.h"
#include "racrypt_digest.h"
#include "racrypt_cipher.h"
#include "racrypt_random.h"

#endif

