; Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license.

_TEXT SEGMENT

PUBLIC RaAesCheckForInstructionSet

;		struct RaAesCtx {
;0	 -520	int nr;
;4   -516	uint32_t key[15][4];
;244 -276	uint32_t rev_key[15][4];
;484 -36	uint32_t iv[RA_BLOCK_LEN_AES / 4];
;500 -20	uint8_t buffer[RA_BLOCK_LEN_AES];
;
;520 -0		struct RaBlockCipher blockCipher;
;		};

;		struct RaBlockCipher {
;0			blockCipherEncryptBlock encryptBlock;
;8			blockCipherDecryptBlock decryptBlock;
;16			enum RaBlockCipherMode opMode;
;24			uint32_t *iv;			// block size / 4
;32			uint8_t *buffer;		// block size
;40			int blockSize;
;44			int bufferFilled;
;		};

CTX_KEY		EQU		[rcx-516]
CTX_NR		EQU		[rcx-520]
CTX_REV_KEY	EQU		[rcx-276]
CTX_ENCRYPT	EQU		[rcx]
CTX_DECRYPT EQU		[rcx+8]


; void RaAesEncryptBlock_x86(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
RaAesEncryptBlock_x86 PROC
	push		rbp
	mov			rbp, rsp
	sub			rsp, 30h
	mov			rax, rsp
	add			rax, 08h
	shr			rax, 4
	shl			rax, 4
	movdqa		[rax], xmm0
	movdqa		[rax+10h], xmm1

	push		rax
	push		rbx

	; rcx: struct RaBlockCipher* blockCipher
	; rdx: const uint8_t* input
	; r8: uint8_t* output

	;struct RaAesCtx {
	;	int nr;									// 0	-520
	;	uint32_t key[15][4];					// 4	-516 
	;	uint32_t rev_key[15][4];				// 244	-276
	;	uint32_t iv[RA_BLOCK_LEN_AES / 4];		// 484	-36
	;	uint8_t buffer[RA_BLOCK_LEN_AES];		// 500	-20
	;
	;	struct RaBlockCipher blockCipher;		// 520
	;};

	lea			rax, CTX_KEY			; ctx->key
	xor			rbx, rbx
	mov			ebx, CTX_NR				; ctx->nr

	movdqu		xmm0, [rdx]

	movdqu		xmm1, [rax]
	pxor		xmm0, xmm1
	movdqu		xmm1, [rax+10h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+20h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+30h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+40h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+50h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+60h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+70h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+80h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+90h]
	aesenc		xmm0, xmm1

	cmp			ebx, 11
	jz			_end_enc_round
	movdqu		xmm1, [rax+0a0h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+0b0h]
	aesenc		xmm0, xmm1

	cmp			ebx, 13
	jz			_end_enc_round
	movdqu		xmm1, [rax+0c0h]
	aesenc		xmm0, xmm1
	movdqu		xmm1, [rax+0d0h]
	aesenc		xmm0, xmm1

_end_enc_round:
	dec			rbx
	shl			rbx, 4
	movdqu		xmm1, [rax+rbx]			; ctx->key[(nr-1) * 16]
	aesenclast	xmm0, xmm1

	movdqu		[r8], xmm0				; output

	;;;;;;;;;;;;;;;;;;;
	pop			rbx
	pop			rax
	movdqa		xmm0, [rax]
	movdqa		xmm1, [rax+10h]

	add			rsp, 30h
	pop			rbp
	ret
RaAesEncryptBlock_x86 ENDP


; void RaAesDecryptBlock_x86(struct RaBlockCipher* blockCipher, const uint8_t* input, uint8_t* output)
RaAesDecryptBlock_x86 PROC
	push		rbp
	mov			rbp, rsp
	sub			rsp, 30h
	mov			rax, rsp
	add			rax, 08h
	shr			rax, 4
	shl			rax, 4
	movdqa		[rax], xmm0
	movdqa		[rax+10h], xmm1

	push		rax
	push		rbx

	; rcx: struct RaBlockCipher* blockCipher
	; rdx: const uint8_t* input
	; r8: uint8_t* output

	;struct RaAesCtx {
	;	int nr;									// 0	-520
	;	uint32_t key[15][4];					// 4	-516 
	;	uint32_t rev_key[15][4];				// 244	-276
	;	uint32_t iv[RA_BLOCK_LEN_AES / 4];		// 484	-36
	;	uint8_t buffer[RA_BLOCK_LEN_AES];		// 500	-20
	;
	;	struct RaBlockCipher blockCipher;		// 520
	;};

	lea			rax, CTX_KEY			; ctx->key
	xor			rbx, rbx
	mov			ebx, CTX_NR				; ctx->nr

	movdqu		xmm0, [rdx]

	dec			rbx
	shl			rbx, 4
	movdqu		xmm1, [rax+rbx]			; ctx->key[(nr-1) * 16]
	pxor		xmm0, xmm1

	cmp			rbx, 0c0h
	lea			rbx, CTX_REV_KEY		; ctx->rev_key
	jz			_start_dec_round13		; nr == 13
	jb			_start_dec_round11		; nr == 11

	movdqu		xmm1, [rbx+0d0h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+0c0h]
	aesdec		xmm0, xmm1
_start_dec_round13:
	movdqu		xmm1, [rbx+0b0h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+0a0h]
	aesdec		xmm0, xmm1
_start_dec_round11:
	movdqu		xmm1, [rbx+90h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+80h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+70h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+60h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+50h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+40h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+30h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+20h]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rbx+10h]			; ctx->rev_key[1]
	aesdec		xmm0, xmm1
	movdqu		xmm1, [rax]				; ctx->key[0]
	aesdeclast	xmm0, xmm1

	movdqu		[r8], xmm0				; output

	;;;;;;;;;;;;;;;;;;;
	pop			rbx
	pop			rax
	movdqa		xmm0, [rax]
	movdqa		xmm1, [rax+10h]

	add			rsp, 30h
	pop			rbp
	ret
RaAesDecryptBlock_x86 ENDP


; void RaAesCheckForInstructionSet(struct RaBlockCipher* blockCipher);
RaAesCheckForInstructionSet PROC
	push		rax
	push		rbx
	push		rcx		; (arg0) ctx
	push		rdx
	push		rcx

	; Look for CPUID.1.ECX[25]
	; EAX = 1
	mov			eax, 1
	cpuid

	bt			ecx, 25
	pop			rcx
	jnc			no_aesni

	mov			rax, RaAesEncryptBlock_x86
	mov			CTX_ENCRYPT, rax			; ctx->encryptBlock

	mov			rax, RaAesDecryptBlock_x86
	mov			CTX_DECRYPT, rax			; ctx->decryptBlock
	
no_aesni:
	pop			rdx
	pop			rcx
	pop			rbx
	pop			rax

	ret

RaAesCheckForInstructionSet ENDP

_TEXT ENDS

END
