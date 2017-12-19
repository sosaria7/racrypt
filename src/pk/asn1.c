/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <racrypt.h>
#include "asn1.h"

#define ASN1_NODE_CHUNK		10
#define ASN1_DATA_STACK		10


struct ASN1NodeChunk {
	struct ASN1Node	node[ASN1_NODE_CHUNK];
	int index;
	struct ASN1NodeChunk *next;
};

struct ASN1Data {
	int dataEnd;
	int dataIndex;
	struct ASN1Node *prevObj;
};

struct ASN1Ctx {
	struct ASN1NodeChunk *head;
	struct ASN1NodeChunk *tail;
	struct ASN1Node *root;
	struct ASN1Node *cur;
	struct ASN1Node **prevLink;
	struct ASN1Node *none;

	uint8_t* data;
	int dataEnd;
	int dataIndex;
	int dataSP;
	struct ASN1Data dataStack[ASN1_DATA_STACK];
};

static int ASN1Push(struct ASN1Ctx *ctx)
{
	struct ASN1Data *stack;
	if (ctx->dataSP >= ASN1_DATA_STACK) {
		return BN_ERR_OUT_OF_BUFFER;
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

	return BN_ERR_SUCCESS;
}

static int ASN1Pop(struct ASN1Ctx *ctx)
{
	struct ASN1Data *stack;
	struct ASN1Node *prevObj;

	if (ctx->dataSP <= 0) {
		return BN_ERR_OUT_OF_BUFFER;
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

	return BN_ERR_SUCCESS;
}

static int ASN1CreateNode(struct ASN1Ctx *ctx)
{
	int result;
	struct ASN1NodeChunk *chunk;
	struct ASN1Node *node;

	chunk = ctx->tail;
	if (chunk->index >= ASN1_NODE_CHUNK) {
		chunk = (struct ASN1NodeChunk *)malloc(sizeof(struct ASN1NodeChunk));
		if (chunk == NULL) {
			result = BN_ERR_OUT_OF_MEMORY;
			goto _EXIT;
		}
		memset(chunk, 0, sizeof(struct ASN1NodeChunk));
		ctx->tail->next = chunk;
		ctx->tail = chunk;
	}

	node = &chunk->node[chunk->index++];
	node->child = ctx->none;
	node->next = ctx->none;

	ctx->cur = node;
	*ctx->prevLink = node;
	ctx->prevLink = &node->next;

	result = BN_ERR_SUCCESS;

_EXIT:
	return result;
}

static int ASN1Read(struct ASN1Ctx *ctx)
{
	int result;
	int length;

	result = ASN1CreateNode(ctx);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	if (ctx->dataIndex + 2 > ctx->dataEnd) {	// at least two bytes are needed
		result = BN_ERR_OUT_OF_BUFFER;
		goto _EXIT;
	}
	ctx->cur->offset = ctx->dataIndex;
	ctx->cur->type = ctx->data[ctx->dataIndex++];
	length = ctx->data[ctx->dataIndex++];
	if (length < 0x80) {
		ctx->cur->dataLength = length;
	}
	else if (length == 0x80) {
		if (ctx->cur->type & ASN1_OBJ_TYPE_CONST) {
			ctx->cur->dataLength = -1;		// indefinite length
			ctx->cur->dataOffset = ctx->dataIndex;
			result = BN_ERR_SUCCESS;
			goto _EXIT;
		}
		else {
			result = BN_ERR_INVALID_DATA;
			goto _EXIT;
		}
	}
	else {
		length -= 0x80;
		if (length > 4) {
			result = BN_ERR_INVALID_DATA;
			goto _EXIT;
		}
		if (ctx->dataIndex + length > ctx->dataEnd) {
			result = BN_ERR_OUT_OF_BUFFER;
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
		result = BN_ERR_OUT_OF_BUFFER;
		goto _EXIT;
	}

	ctx->dataIndex += ctx->cur->dataLength;

	result = BN_ERR_SUCCESS;
_EXIT:
	return result;
}

static int ASN1Parse(struct ASN1Ctx *ctx)
{
	int result;

	while (ctx->dataIndex < ctx->dataEnd) {
		result = ASN1Read(ctx);
		if (result != BN_ERR_SUCCESS) goto _EXIT;

		if (ctx->cur->type & ASN1_OBJ_TYPE_CONST) {
			ASN1Push(ctx);
			continue;
		}

		if (ctx->dataIndex >= ctx->dataEnd ||
			(ctx->cur->type == 0 && ctx->cur->dataLength == 0) ) {		// end-of-content
			result = ASN1Pop(ctx);
			if (result == BN_ERR_OUT_OF_BUFFER) {
				result = BN_ERR_SUCCESS;
				break;
			}
			if (result != BN_ERR_SUCCESS) goto _EXIT;
		}
	};

	result = BN_ERR_SUCCESS;
_EXIT:
	return result;
}

int ASN1CreateContext(uint8_t *data, int dataLen, /*out*/struct ASN1Ctx **ctxp)
{
	int result;
	struct ASN1Ctx *ctx;
	ctx = (struct ASN1Ctx *)malloc(sizeof(struct ASN1Ctx));
	if (ctx == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	memset(ctx, 0, sizeof(struct ASN1Ctx));

	ctx->head = (struct ASN1NodeChunk *)malloc(sizeof(struct ASN1NodeChunk));
	if (ctx->head == NULL) {
		result = BN_ERR_OUT_OF_MEMORY;
		goto _EXIT;
	}
	memset(ctx->head, 0, sizeof(struct ASN1NodeChunk));
	ctx->tail = ctx->head;

	ctx->prevLink = &ctx->none;
	result = ASN1CreateNode(ctx);
	ctx->data = data;
	ctx->dataEnd = dataLen;
	ctx->none->next = ctx->none;
	ctx->none->child = ctx->none;
	ctx->none->type = ASN1_OBJ_NONE;
	ctx->root = ctx->none;

	ctx->prevLink = &ctx->root;

	result = ASN1Parse(ctx);
	if (result != BN_ERR_SUCCESS) goto _EXIT;

	*ctxp = ctx;
	ctx = NULL;
	result = BN_ERR_SUCCESS;
_EXIT:
	if (ctx != NULL) {
		ASN1DestroyContext(ctx);
	}
	return result;
}

void ASN1DestroyContext(struct ASN1Ctx *ctx)
{
	struct ASN1NodeChunk *chunk;
	struct ASN1NodeChunk *next;
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

int ASN1GetRoot(struct ASN1Ctx *ctx, /*out*/struct ASN1Node **nodep)
{
	*nodep = ctx->root;
	return BN_ERR_SUCCESS;
}
