; Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license.

.686p
.XMM
.model flat, C

_DATA SEGMENT

align 16
order_byte	db	0fh, 0eh, 0dh, 0ch, 0bh, 0ah, 09h, 08h, 07h, 06h, 05h, 04h, 03h, 02h, 01h, 00h
_DATA ENDS

_TEXT SEGMENT

PUBLIC RaSha1CheckForInstructionSet

;		struct RaSha1Ctx
;		{
;0			uint32_t totalLen_h;
;4			uint32_t totalLen_l;
;8			uint32_t h[5];
;28			uint8_t buffer[64];
;92			void (*fnRaSha1Process)(struct RaSha1Ctx* ctx, const uint8_t data[64]);
;		};

CTX_H		EQU		[ecx+8]
CTX_PROCESS	EQU		[ecx+92]
ARG0		EQU		[ebp+08h]
ARG1		EQU		[ebp+0ch]


; static void RaSha1Process_x86(struct RaSha1Ctx *ctx, const uint8_t data[64])
RaSha1Process_x86 PROC
	push		ebp
	mov			ebp, esp
	sub			esp, 90h
	mov			eax, esp
	add			eax, 0ch
	shr			eax, 4
	shl			eax, 4
	movdqa		[eax], xmm0
	movdqa		[eax+10h], xmm1
	movdqa		[eax+20h], xmm2
	movdqa		[eax+30h], xmm3
	movdqa		[eax+40h], xmm4
	movdqa		[eax+50h], xmm5
	movdqa		[eax+60h], xmm6
	movdqa		[eax+70h], xmm7
	push		eax
	push		ecx
	push		edx

	; [ebp+08h]: struct RaSha1Ctx *ctx
	; [ebp+0ch]: const uint8_t data[64]

	mov			ecx, ARG0
	mov			edx, ARG1

	lea			eax, CTX_H				; (arg0) ctx->h

	movdqu		xmm0, [eax]				; abcd
	movd		xmm1, dword ptr [eax+16]	; e
	movdqu		xmm3, [edx]				; (arg1) w0...w3
	movdqu		xmm4, [edx+16]			; w4...w7
	movdqu		xmm5, [edx+32]			; w8...w11
	movdqu		xmm6, [edx+48]			; w12..w15

	pshufd		xmm0, xmm0,	1bh			; 0b00011011 change word order
	pshufd		xmm1, xmm1, 1bh			; 0b00011011 change word order
	pshufb		xmm3, order_byte		; endian change
	pshufb		xmm4, order_byte		; endian change
	pshufb		xmm5, order_byte		; endian change
	pshufb		xmm6, order_byte		; endian change

	movdqa		xmm2, xmm0				; abcd_save
	paddd		xmm1, xmm3				; xmm1 = (w0 + e)...w3
	sha1rnds4	xmm0, xmm1, 0			; r0~r3

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm4				; xmm2 = (w4 + e)...w7
	sha1rnds4	xmm0, xmm2, 0			; r4~r7

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm5				; xmm1 = (w8 + e)...w11
	sha1rnds4	xmm0, xmm1, 0			; r8~r11

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm6				; xmm2 = (w12 + e)...w15
	sha1rnds4	xmm0, xmm2, 0			; r12~r15

	;;;;;;;;;;
	sha1msg1	xmm3, xmm4
	pxor		xmm3, xmm5
	sha1msg2	xmm3, xmm6

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm3
	sha1rnds4	xmm0, xmm1, 0			; r16~r19

	;;;;;;;;;;
	sha1msg1	xmm4, xmm5
	pxor		xmm4, xmm6
	sha1msg2	xmm4, xmm3

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm4
	sha1rnds4	xmm0, xmm2, 1			; r20~r23

	sha1msg1	xmm5, xmm6
	pxor		xmm5, xmm3
	sha1msg2	xmm5, xmm4

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm5
	sha1rnds4	xmm0, xmm1, 1			; r24~r27

	sha1msg1	xmm6, xmm3
	pxor		xmm6, xmm4
	sha1msg2	xmm6, xmm5

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm6
	sha1rnds4	xmm0, xmm2, 1			; r28~r31

	sha1msg1	xmm3, xmm4
	pxor		xmm3, xmm5
	sha1msg2	xmm3, xmm6

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm3
	sha1rnds4	xmm0, xmm1, 1			; r32~r35

	sha1msg1	xmm4, xmm5
	pxor		xmm4, xmm6
	sha1msg2	xmm4, xmm3

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm4
	sha1rnds4	xmm0, xmm2, 1			; r36~r39

	;;;;;;;;;;
	sha1msg1	xmm5, xmm6
	pxor		xmm5, xmm3
	sha1msg2	xmm5, xmm4

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm5
	sha1rnds4	xmm0, xmm1, 2			; r40~r43

	sha1msg1	xmm6, xmm3
	pxor		xmm6, xmm4
	sha1msg2	xmm6, xmm5

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm6
	sha1rnds4	xmm0, xmm2, 2			; r44~r47

	sha1msg1	xmm3, xmm4
	pxor		xmm3, xmm5
	sha1msg2	xmm3, xmm6

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm3
	sha1rnds4	xmm0, xmm1, 2			; r48~r51

	sha1msg1	xmm4, xmm5
	pxor		xmm4, xmm6
	sha1msg2	xmm4, xmm3

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm4
	sha1rnds4	xmm0, xmm2, 2			; r52~r55

	sha1msg1	xmm5, xmm6
	pxor		xmm5, xmm3
	sha1msg2	xmm5, xmm4

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm5
	sha1rnds4	xmm0, xmm1, 2			; r56~r59

	;;;;;;;;;;
	sha1msg1	xmm6, xmm3
	pxor		xmm6, xmm4
	sha1msg2	xmm6, xmm5

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm6
	sha1rnds4	xmm0, xmm2, 3			; r60~r63

	sha1msg1	xmm3, xmm4
	pxor		xmm3, xmm5
	sha1msg2	xmm3, xmm6

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm3
	sha1rnds4	xmm0, xmm1, 3			; r64~r67

	sha1msg1	xmm4, xmm5
	pxor		xmm4, xmm6
	sha1msg2	xmm4, xmm3

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm4
	sha1rnds4	xmm0, xmm2, 3			; r68~r71

	sha1msg1	xmm5, xmm6
	pxor		xmm5, xmm3
	sha1msg2	xmm5, xmm4

	movdqa		xmm2, xmm0				; abcd_save
	sha1nexte	xmm1, xmm5
	sha1rnds4	xmm0, xmm1, 3			; r72~r75

	sha1msg1	xmm6, xmm3
	pxor		xmm6, xmm4
	sha1msg2	xmm6, xmm5

	movdqa		xmm1, xmm0				; abcd_save
	sha1nexte	xmm2, xmm6
	sha1rnds4	xmm0, xmm2, 3			; r76~r79

	movdqu		xmm2, [eax]
	pshufd		xmm0, xmm0, 1bh			; 0b00011011 change word order
	paddd		xmm2, xmm0
	movdqu		[eax], xmm2				; a, b, c, d

	pxor		xmm3, xmm3
	sha1nexte	xmm1, xmm3

	movd		xmm2, dword ptr [eax+16]
	pshufd		xmm1, xmm1, 1bh			; 0b00011011 change word order
	paddd		xmm2, xmm1
	movd		dword ptr [eax+16], xmm2	; e

	pop			edx
	pop			ecx
	pop			eax
	movdqa		xmm0, [eax]
	movdqa		xmm1, [eax+10h]
	movdqa		xmm2, [eax+20h]
	movdqa		xmm3, [eax+30h]
	movdqa		xmm4, [eax+40h]
	movdqa		xmm5, [eax+50h]
	movdqa		xmm6, [eax+60h]
	movdqa		xmm7, [eax+70h]

	add			esp, 90h
	pop			ebp
	ret
RaSha1Process_x86 ENDP


; void RaSha1CheckForInstructionSet( struct RaSha1Ctx *ctx )
RaSha1CheckForInstructionSet PROC
	push		ebp
	mov			ebp, esp
	push		eax
	push		ebx
	push		ecx
	push		edx

	; Look for CPUID.7.0.EBX[29]
	; EAX = 7, ECX = 0
	mov			eax, 7
	mov			ecx, 0
	cpuid

	bt			ebx, 29
	jnc			no_shae
	mov			ecx, ARG0						; (arg0) struct RaSha1Ctx *ctx
	mov			eax, RaSha1Process_x86
	mov			CTX_PROCESS, eax				; ctx->fnRaSha1Process
	
no_shae:
	pop			edx
	pop			ecx
	pop			ebx
	pop			eax

	pop			ebp
	ret

RaSha1CheckForInstructionSet ENDP

_TEXT ENDS

END
