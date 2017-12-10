/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#pragma once
#ifndef __BN_ASN1_H__
#define __BN_ASN1_H__

#define ASN1_OBJ_SEQUENCE			0x30
#define ASN1_OBJ_INTEGER			0x02
#define ASN1_OBJ_OCTET_STRING		0x04
#define ASN1_OBJ_IDENTIFIER			0x06
#define ASN1_OBJ_NULL				0x05
#define ASN1_OBJ_BIT_STRING			0x03
#define ASN1_OBJ_NONE				-1

#define ASN1_OBJ_TYPE_CONST			0x20

struct ASN1Node {
	int type;
	int offset;
	int dataOffset;
	int dataLength;
	struct ASN1Node *child;
	struct ASN1Node *next;
};
struct ASN1Ctx;

int ASN1CreateContext(uint8_t *data, int dataLen, struct ASN1Ctx **ctxp);
void ASN1DestroyContext(struct ASN1Ctx *ctx);
int ASN1GetRoot(struct ASN1Ctx *ctx, /*out*/struct ASN1Node **nodep);

#endif
