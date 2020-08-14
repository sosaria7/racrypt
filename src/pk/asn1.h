/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifndef __BN_ASN1_H__
#define __BN_ASN1_H__

#ifdef __cplusplus
extern "C" {
#endif

#define RA_ASN1_OBJ_SEQUENCE			0x30
#define RA_ASN1_OBJ_INTEGER				0x02
#define RA_ASN1_OBJ_OCTET_STRING		0x04
#define RA_ASN1_OBJ_IDENTIFIER			0x06
#define RA_ASN1_OBJ_NULL				0x05
#define RA_ASN1_OBJ_BIT_STRING			0x03
#define RA_ASN1_OBJ_NONE				-1

#define RA_ASN1_OBJ_TYPE_CONST			0x20

	struct RaAsn1Node {
		int type;
		int offset;
		int dataOffset;
		int dataLength;
		struct RaAsn1Node* child;
		struct RaAsn1Node* next;
	};
	struct RaAsn1Ctx;

	int RaAsn1CreateContext(const uint8_t* data, int dataLen, struct RaAsn1Ctx** ctxp);
	void RaAsn1DestroyContext(struct RaAsn1Ctx* ctx);
	int RaAsn1GetRoot(struct RaAsn1Ctx* ctx, /*out*/struct RaAsn1Node** nodep);

#ifdef __cplusplus
}
#endif

#endif
