/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <racrypt.h>

#include <stdlib.h>
#include <string.h>

#include "asn1.h"

#define RA_ASN1_NODE_CHUNK		10
#define RA_ASN1_DATA_STACK		10


struct RaAsn1NodeChunk {
	struct RaAsn1Node	node[RA_ASN1_NODE_CHUNK];
	int index;
	struct RaAsn1NodeChunk *next;
};

struct ASN1Data {
	int dataEnd;
	int dataIndex;
	struct RaAsn1Node *prevObj;
};

struct RaAsn1Ctx {
	struct RaAsn1NodeChunk *head;
	struct RaAsn1NodeChunk *tail;
	struct RaAsn1Node *root;
	struct RaAsn1Node *cur;
	struct RaAsn1Node **prevLink;
	struct RaAsn1Node *none;

	const uint8_t* data;
	int dataEnd;
	int dataIndex;
	int dataSP;
	struct ASN1Data dataStack[RA_ASN1_DATA_STACK];
};

static int ASN1Push(struct RaAsn1Ctx *ctx)
{
	struct ASN1Data *stack;
	if (ctx->dataSP >= RA_ASN1_DATA_STACK) {
		return RA_ERR_OUT_OF_BUFFER;
	}

	stack = &ctx->dataStack[ctx->dataSP++];
	stack->dataEnd = ctx->dataEnd;
	stack->dataIndex = ctx->dataIndex;
	stack->prevObj = ctx->cur;
	if (ctx->cur->dataLength < 0) {	// indefinite length
		stack->dataIndex = -1;		// next index is not set yet.
		// ctx->dataEnd not changed
	}
	else {
		ctx->dataEnd = ctx->cur->dataOffset + ctx->cur->dataLength;
	}
	ctx->prevLink = &ctx->cur->child;
	ctx->dataIndex = ctx->cur->dataOffset;

	return RA_ERR_SUCCESS;
}

static int ASN1Pop(struct RaAsn1Ctx *ctx)
{
	struct ASN1Data *stack;
	struct RaAsn1Node *prevObj;

	if (ctx->dataSP <= 0) {
		return RA_ERR_OUT_OF_BUFFER;
	}
	stack = &ctx->dataStack[--ctx->dataSP];
	prevObj = stack->prevObj;
	ctx->dataEnd = stack->dataEnd;
	ctx->prevLink = &prevObj->next;
	if (stack->dataIndex > 0) {
		ctx->dataIndex = stack->dataIndex;
	}
	if (prevObj->dataLength < 0) {	// indefinite length
		prevObj->dataLength = ctx->dataIndex - prevObj->dataOffset - 2;
	}

	return RA_ERR_SUCCESS;
}

static int RaAsn1CreateNode(struct RaAsn1Ctx *ctx)
{
	int result;
	struct RaAsn1NodeChunk *chunk;
	struct RaAsn1Node *node;

	chunk = ctx->tail;
	if (chunk->index >= RA_ASN1_NODE_CHUNK) {
		chunk = (struct RaAsn1NodeChunk *)malloc(sizeof(struct RaAsn1NodeChunk));
		if (chunk == NULL) {
			result = RA_ERR_OUT_OF_MEMORY;
			goto _EXIT;
		}
		memset(chunk, 0, sizeof(struct RaAsn1NodeChunk));
		ctx->tail->next = chunk;
		ctx->tail = chunk;
	}

	node = &chunk->node[chunk->index++];
	node->child = ctx->none;
	node->next = ctx->none;

	ctx->cur = node;
	*ctx->prevLink = node;
	ctx->prevLink = &node->next;

	result = RA_ERR_SUCCESS;

_EXIT:
	return result;
}

static int ASN1Read(struct RaAsn1Ctx *ctx)
{
	int result;
	int length;

	result = RaAsn1CreateNode(ctx);
	if (result != RA_ERR_SUCCESS) goto _EXIT;

	if (ctx->dataIndex + 2 > ctx->dataEnd) {	// at least two bytes are needed
		result = RA_ERR_OUT_OF_BUFFER;
		goto _EXIT;
	}
	ctx->cur->offset = ctx->dataIndex;
	ctx->cur->type = ctx->data[ctx->dataIndex++];
	length = ctx->data[ctx->dataIndex++];
	if (length < 0x80) {
		ctx->cur->dataLength = length;
	}
	else if (length == 0x80) {
		if (ctx->cur->type & RA_ASN1_OBJ_TYPE_CONST) {
			ctx->cur->dataLength = -1;		// indefinite length
			ctx->cur->dataOffset = ctx->dataIndex;
			result = RA_ERR_SUCCESS;
			goto _EXIT;
		}
		else {
			result = RA_ERR_INVALID_DATA;
			goto _EXIT;
		}
	}
	else {
		length -= 0x80;
		if (length > 4) {
			result = RA_ERR_INVALID_DATA;
			goto _EXIT;
		}
		if (ctx->dataIndex + length > ctx->dataEnd) {
			result = RA_ERR_OUT_OF_BUFFER;
			goto _EXIT;
		}
		ctx->cur->dataLength = 0;
		while (length-- > 0) {
			ctx->cur->dataLength <<= 8;
			ctx->cur->dataLength += ctx->data[ctx->dataIndex++];
		}
	}

	ctx->cur->dataOffset = ctx->dataIndex;

	if (ctx->cur->dataOffset + ctx->cur->dataLength > ctx->dataEnd) {
		result = RA_ERR_OUT_OF_BUFFER;
		goto _EXIT;
	}

	ctx->dataIndex += ctx->cur->dataLength;

	result = RA_ERR_SUCCESS;
_EXIT:
	return result;
}

static int ASN1Parse(struct RaAsn1Ctx *ctx)
{
	int result;

	while (ctx->dataIndex < ctx->dataEnd) {
		result = ASN1Read(ctx);
		if (result != RA_ERR_SUCCESS) goto _EXIT;

		if (ctx->cur->type & RA_ASN1_OBJ_TYPE_CONST) {
			ASN1Push(ctx);
			continue;
		}

		if (ctx->dataIndex >= ctx->dataEnd ||
			(ctx->cur->type == 0 && ctx->cur->dataLength == 0) ) {		// end-of-content
			result = ASN1Pop(ctx);
			if (result == RA_ERR_OUT_OF_BUFFER) {
				result = RA_ERR_SUCCESS;
				break;
			}
			if (result != RA_ERR_SUCCESS) goto _EXIT;
		}
	};

	result = RA_ERR_SUCCESS;
_EXIT:
	return result;
}

int RaAsn1CreateContext(const uint8_t *data, int dataLen, /*out*/struct RaAsn1Ctx **ctxp)
{
	int result;
	struct RaAsn1Ctx *ctx;
	ctx = (struct RaAsn1Ctx *)malloc(sizeof(struct RaAsn1Ctx));
	if (ctx == NULL) {
		result = RA_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	memset(ctx, 0, sizeof(struct RaAsn1Ctx));

	ctx->head = (struct RaAsn1NodeChunk *)malloc(sizeof(struct RaAsn1NodeChunk));
	if (ctx->head == NULL) {
		result = RA_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	memset(ctx->head, 0, sizeof(struct RaAsn1NodeChunk));
	ctx->tail = ctx->head;

	ctx->prevLink = &ctx->none;
	result = RaAsn1CreateNode(ctx);
	ctx->data = data;
	ctx->dataEnd = dataLen;
	ctx->none->next = ctx->none;
	ctx->none->child = ctx->none;
	ctx->none->type = RA_ASN1_OBJ_NONE;
	ctx->root = ctx->none;

	ctx->prevLink = &ctx->root;

	result = ASN1Parse(ctx);
	if (result != RA_ERR_SUCCESS) goto _EXIT;

	*ctxp = ctx;
	ctx = NULL;
	result = RA_ERR_SUCCESS;
_EXIT:
	if (ctx != NULL) {
		RaAsn1DestroyContext(ctx);
	}
	return result;
}

void RaAsn1DestroyContext(struct RaAsn1Ctx *ctx)
{
	struct RaAsn1NodeChunk *chunk;
	struct RaAsn1NodeChunk *next;
	if (ctx != NULL) {
		chunk = ctx->head;
		while (chunk != NULL) {
			next = chunk->next;
			free(chunk);
			chunk = next;
		}
		free(ctx);
	}
}

int RaAsn1GetRoot(struct RaAsn1Ctx *ctx, /*out*/struct RaAsn1Node **nodep)
{
	*nodep = ctx->root;
	return RA_ERR_SUCCESS;
}
