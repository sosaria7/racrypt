; Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license.

.686p
.XMM
.model flat, C

_TEXT SEGMENT

PUBLIC RaAesCheckForIntelAesNI

;		struct RaAesCtx {
;0	 -516	int nr;
;4   -512	uint32_t key[15][4];
;244 -272	uint32_t rev_key[15][4];
;484 -32	uint32_t iv[RA_BLOCK_LEN_AES / 4];
;500 -16	uint8_t buffer[RA_BLOCK_LEN_AES];
;
;516 -0		struct RaBlockCipher blockCipher;
;		};

;		struct RaBlockCipher {
;0			blockCipherEncryptBlock encryptBlock;
;4			blockCipherDecryptBlock decryptBlock;
;8			enum RaBlockCipherMode opMode;
;12			uint32_t *iv;			// block size / 4
;16			uint8_t *buffer;		// block size
;20			int blockSize;
;24			int bufferFilled;
;		};

CTX_KEY		EQU		[ecx-512]
CTX_NR		EQU		[ecx-516]
CTX_REV_KEY	EQU		[ecx-272]
CTX_ENCRYPT	EQU		[ecx]
CTX_DECRYPT EQU		[ecx+4]
ARG0		EQU		[ebp+08h]
ARG1		EQU		[ebp+0ch]
ARG2		EQU		[ebp+10h]


; static void RaAesEncryptBlock_x86(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
RaAesEncryptBlock_x86 PROC
	; [ebp+08h]: struct RaBlockCipher* blockCipher
	; [ebp+0ch]: const uint8_t* input
	; [ebp+10h]: uint8_t* output

	push		ebp
	mov			ebp, esp
	sub			esp, 30h
	mov			eax, esp
	add			eax, 0ch
	shr			eax, 4
	shl			eax, 4
	movdqa		[eax], xmm0
	movdqa		[eax+10h], xmm1

	push		eax
	push		ebx
	push		ecx
	push		edx

	mov			ecx, ARG0				; (arg0) struct RaBlockCipher* blockCipher
	mov			edx, ARG1				; (arg1) const uint8_t* input

	lea			eax, CTX_KEY			; ctx->key
	xor			ebx, ebx
	mov			ebx, CTX_NR				; ctx->nr

	movdqu		xmm0, [edx]

	movdqu		xmm1, [eax]
	pxor		xmm0, xmm1
	movdqu		xmm1, [eax+10h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+20h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+30h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+40h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+50h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+60h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+70h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+80h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+90h]
	aesenc		xmm0, xmm1

	cmp			ebx, 11
	jz			_end_enc_round
	movdqu		xmm1, [eax+0a0h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+0b0h]
	aesenc		xmm0, xmm1

	cmp			ebx, 13
	jz			_end_enc_round
	movdqu		xmm1, [eax+0c0h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [eax+0d0h]
	aesenc		xmm0, xmm1

_end_enc_round:
	dec			ebx
	shl			ebx, 4
	movdqu		xmm1, [eax+ebx]			; ctx->key[(nr-1) * 16]
	aesenclast	xmm0, xmm1

	mov			eax, [ebp+10h]			; (arg2) uint8_t* output
	movdqu		[eax], xmm0				; output

	;;;;;;;;;;;;;;;;;;;
	pop			edx
	pop			ecx
	pop			ebx
	pop			eax
	movdqa		xmm0, [eax]
	movdqa		xmm1, [eax+10h]

	add			esp, 30h
	pop			ebp
	ret
RaAesEncryptBlock_x86 ENDP


; static void RaAesDecryptBlock_x86(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
RaAesDecryptBlock_x86 PROC
	; [ebp+08h]: struct RaBlockCipher* blockCipher
	; [ebp+0ch]: const uint8_t* input
	; [ebp+10h]: uint8_t* output

	push		ebp
	mov			ebp, esp
	sub			esp, 30h
	mov			eax, esp
	add			eax, 0ch
	shr			eax, 4
	shl			eax, 4
	movdqa		[eax], xmm0
	movdqa		[eax+10h], xmm1

	push		eax
	push		ebx
	push		ecx
	push		edx

	mov			ecx, ARG0				; (arg0) struct RaBlockCipher* blockCipher
	mov			edx, ARG1				; (arg1) const uint8_t* input

	lea			eax, CTX_KEY			; ctx->key
	mov			ebx, CTX_NR				; ctx->nr

	movdqu		xmm0, [edx]

	dec			ebx
	shl			ebx, 4
	movdqu		xmm1, [eax+ebx]			; ctx->key[(nr-1) * 16]
	pxor		xmm0, xmm1

	cmp			ebx, 0c0h
	lea			ebx, CTX_REV_KEY		; ctx->rev_key
	jz			_start_dec_round13		; nr == 13
	jb			_start_dec_round11		; nr == 11

	movdqu		xmm1, [ebx+0d0h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+0c0h]
	aesdec		xmm0, xmm1
_start_dec_round13:
	movdqu		xmm1, [ebx+0b0h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+0a0h]
	aesdec		xmm0, xmm1
_start_dec_round11:
	movdqu		xmm1, [ebx+90h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+80h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+70h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+60h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+50h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+40h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+30h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+20h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [ebx+10h]			; ctx->rev_key[1]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [eax]				; ctx->key[0]
	aesdeclast	xmm0, xmm1

	mov			eax, [ebp+10h]			; (arg2) uint8_t* output
	movdqu		[eax], xmm0				; output

	;;;;;;;;;;;;;;;;;;;
	pop			edx
	pop			ecx
	pop			ebx
	pop			eax
	movdqa		xmm0, [eax]
	movdqa		xmm1, [eax+10h]

	add			esp, 30h
	pop			ebp
	ret
RaAesDecryptBlock_x86 ENDP


; void RaAesCheckForIntelAesNI(struct RaBlockCipher* blockCipher);
RaAesCheckForIntelAesNI PROC
	push		ebp
	mov			ebp, esp
	push		eax
	push		ebx
	push		ecx
	push		edx

	; Look for CPUID.1.ECX[25]
	; EAX = 1
	mov			eax, 1
	cpuid

	bt			ecx, 25
	jnc			no_aesni

	mov			ecx, ARG0					; (arg0) struct RaBlockCipher* blockCipher
	mov			eax, RaAesEncryptBlock_x86
	mov			CTX_ENCRYPT, eax			; ctx->encryptBlock

	mov			eax, RaAesDecryptBlock_x86
	mov			CTX_DECRYPT, eax			; ctx->decryptBlock
	
no_aesni:
	pop			edx
	pop			ecx
	pop			ebx
	pop			eax

	pop			ebp
	ret

RaAesCheckForIntelAesNI ENDP

_TEXT ENDS

END
