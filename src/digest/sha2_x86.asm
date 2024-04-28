; Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license.

.686p
.XMM
.model flat, C

_DATA SEGMENT

align 16
order_byte	db	03h, 02h, 01h, 00h, 07h, 06h, 05h, 04h, 0bh, 0ah, 09h, 08h, 0fh, 0eh, 0dh, 0ch

raSha256K	dd	0428a2f98h, 071374491h, 0b5c0fbcfh, 0e9b5dba5h, 03956c25bh, 059f111f1h, 0923f82a4h, 0ab1c5ed5h
			dd	0d807aa98h, 012835b01h, 0243185beh, 0550c7dc3h, 072be5d74h, 080deb1feh, 09bdc06a7h, 0c19bf174h
			dd	0e49b69c1h, 0efbe4786h, 00fc19dc6h, 0240ca1cch, 02de92c6fh, 04a7484aah, 05cb0a9dch, 076f988dah
			dd	0983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h, 0c6e00bf3h, 0d5a79147h, 006ca6351h, 014292967h
			dd	027b70a85h, 02e1b2138h, 04d2c6dfch, 053380d13h, 0650a7354h, 0766a0abbh, 081c2c92eh, 092722c85h
			dd	0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h, 0d192e819h, 0d6990624h, 0f40e3585h, 0106aa070h
			dd	019a4c116h, 01e376c08h, 02748774ch, 034b0bcb5h, 0391c0cb3h, 04ed8aa4ah, 05b9cca4fh, 0682e6ff3h
			dd	0748f82eeh, 078a5636fh, 084c87814h, 08cc70208h, 090befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h

_DATA ENDS

_TEXT SEGMENT

PUBLIC RaSha256CheckForInstructionSet

;		struct RaSha2Ctx
;		{
; 0			uint64_t totalLen_hh;
; 8			uint32_t totalLen_h;
; 12		uint32_t totalLen_l;
; 16		uint64_t h[8];
; 80		uint8_t buffer[128];
; 208		enum RaDigestAlgorithm	algorithm;
; 212		union {
;				void (*fnRaSha256Process)(struct RaSha2Ctx* ctx, const uint8_t data[64]);
;				void (*fnRaSha512Process)(struct RaSha2Ctx* ctx, const uint8_t data[128]);
;			};
;		};

CTX_H		EQU		[ecx+16]
CTX_PROCESS	EQU		[ecx+212]
ARG0		EQU		[ebp+08h]
ARG1		EQU		[ebp+0ch]


; static void RaSha256Process_x86(struct RaSha2Ctx *ctx, const uint8_t data[64])
RaSha256Process_x86 PROC
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
	push		ebx
	push		ecx
	push		edx

	; [ebp+08h]: struct RaSha1Ctx *ctx
	; [ebp+0ch]: const uint8_t data[64]
	mov			ecx, ARG0
	mov			edx, ARG1

	lea			eax, CTX_H				; (arg0) ctx->h
	mov			ebx, OFFSET raSha256K

	; xmm0: msg
	; xmm1: abef
	; xmm2: cdgh 
	; xmm3: temp 
	; xmm4: w3.w2.w1.w0
	; xmm5: w7.w6.w5.w4
	; xmm6: w11.w10.w9.w8
	; xmm7: w15.w14.w13.w12

	; Since ctx->h is a pointer to a 64-bit integer, the ABEF is assembled from the lower 32-bit values.
	movdqu		xmm3, [eax]				; .b.a
	movdqu		xmm1, [eax+20h]			; .f.e
	pshufd		xmm3, xmm3, 72h			; ..ab		$0b01110010
	pshufd		xmm1, xmm1, 72h			; ..ef		$0b01110010
	punpcklqdq	xmm1, xmm3				; abef

	movdqu		xmm3, [eax+10h]			; .d.c
	movdqu		xmm2, [eax+30h]			; .h.g
	pshufd		xmm3, xmm3, 72h			; ..cd		$0b01110010
	pshufd		xmm2, xmm2, 72h			; ..gh		$0b01110010
	punpcklqdq	xmm2, xmm3				; cdgh

	;;;;;;;;;;;;;;;;;;;
	; SHA2_P(0~3)
	; read 1st 128bit message
	movdqu		xmm0, [edx]				; w0...w3
	pshufb		xmm0, order_byte		; w3.w2.w1.w0
	movdqa		xmm4, xmm0

	; add four raSha256K values
	movdqa		xmm3, [ebx]
	paddd		xmm0, xmm3

	; do sha256rnds2
	sha256rnds2	xmm2, xmm1, xmm0		; r0~r1, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w1.w0.w3.w2	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r2~r3, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_P(4~7)
	; read 2nd 128bit message
	movdqu		xmm0, [edx+10h]			; w4...w7
	pshufb		xmm0, order_byte		; w7.w6.w5.w4
	movdqa		xmm5, xmm0

	; add next four raSha256K values
	movdqa		xmm3, [ebx+10h]
	paddd		xmm0, xmm3

	; do sha256rnds2
	sha256rnds2	xmm2, xmm1, xmm0		; r4~r5, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w5.w4.w7.w6	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r6~r7, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_P(8~11)
	; read 3rd 128bit message
	movdqu		xmm0, [edx+20h]			; w8...w11
	pshufb		xmm0, order_byte		; w11.w10.w9.w8
	movdqa		xmm6, xmm0

	; add next four raSha256K values
	movdqa		xmm3, [ebx+20h]
	paddd		xmm0, xmm3

	; do sha256rnds2
	sha256rnds2	xmm2, xmm1, xmm0		; r8~r9, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w9.w8.w11.w10	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r10~r11, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_P(12~15)
	; read 4th 128bit message
	movdqu		xmm0, [edx+30h]			; w12...w15
	pshufb		xmm0, order_byte		; w15.w14.w13.w12
	movdqa		xmm7, xmm0

	; add next four raSha256K values
	movdqa		xmm3, [ebx+30h]
	paddd		xmm0, xmm3

	; do sha256rnds2
	sha256rnds2	xmm2, xmm1, xmm0		; r12~r13, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w13.w12.w15.w14	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r14~r15, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(16~19)
	sha256msg1	xmm4, xmm5				; ...w4. : w3.w2.w1.w0
	movdqa		xmm3, xmm7				; xmm3 = w15.w14.w13.w12
	palignr		xmm3, xmm6, 4			; xmm3 = w12.w11.w10.w9
	paddd		xmm4, xmm3				; w12.w11.w10.w9 + w3.w2.w1.w0
	sha256msg2	xmm4, xmm7				; w15.w14... : w3.w2.w1.w0
	movdqa		xmm0, xmm4

	; SHA2_P(16~19)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+40h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r16~r17, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w1.w0.w3.w2	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r18~r19, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(20~23)
	sha256msg1	xmm5, xmm6				; ...w8. : w7.w6.w5.w4
	movdqa		xmm3, xmm4				; xmm3 = w3.w2.w1.w0
	palignr		xmm3, xmm7, 4			; xmm3 = w0.w15.w14.w13
	paddd		xmm5, xmm3				; w0.w15.w14.w13 + w7.w6.w5.w4
	sha256msg2	xmm5, xmm4				; w3.w2... : w7.w6.w5.w4
	movdqa		xmm0, xmm5

	; SHA2_P(20~23)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+50h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r20~r21, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w5.w4.w7.w6	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r22~r23, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(24~27)
	sha256msg1	xmm6, xmm7				; ...w12. : w11.w10.w9.w8
	movdqa		xmm3, xmm5				; xmm3 = w7.w6.w5.w4
	palignr		xmm3, xmm4, 4			; xmm3 = w4.w3.w2.w1
	paddd		xmm6, xmm3				; w4.w3.w2.w1 + w11.w10.w9.w8
	sha256msg2	xmm6, xmm5				; w7.w6... : w11.w10.w9.w8
	movdqa		xmm0, xmm6

	; SHA2_P(24~27)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+60h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r24~r25, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w9.w8.w11.w10	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r26~r27, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(28~31)
	sha256msg1	xmm7, xmm4				; ...w0. : w15.w14.w13.w12
	movdqa		xmm3, xmm6				; xmm3 = w11.w10.w9.w8
	palignr		xmm3, xmm5, 4			; xmm3 = w8.w7.w6.w5
	paddd		xmm7, xmm3				; w8.w7.w6.w5 + w15.w14.w13.w12
	sha256msg2	xmm7, xmm6				; w11.w10... : w15.w14.w13.w12
	movdqa		xmm0, xmm7

	; SHA2_P(28~31)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+70h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r28~r29, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w13.w12.w15.w14	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r30~r31, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(32~35)
	sha256msg1	xmm4, xmm5				; ...w4. : w3.w2.w1.w0
	movdqa		xmm3, xmm7				; xmm3 = ...w12
	palignr		xmm3, xmm6, 4			; xmm3 = w12.w11.w10.w9
	paddd		xmm4, xmm3				; w12.w11.w10.w9 + w3.w2.w1.w0
	sha256msg2	xmm4, xmm7				; w15.w14... : w3.w2.w1.w0
	movdqa		xmm0, xmm4

	; SHA2_P(32~35)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+80h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r32~r33, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w1.w0.w3.w2	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r34~r35, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(36~39)
	sha256msg1	xmm5, xmm6				; ...w8. : w7.w6.w5.w4
	movdqa		xmm3, xmm4				; xmm3 = ...w0
	palignr		xmm3, xmm7, 4			; xmm3 = w0.w15.w14.w13
	paddd		xmm5, xmm3				; w0.w15.w14.w13 + w7.w6.w5.w4
	sha256msg2	xmm5, xmm4				; w3.w2... : w7.w6.w5.w4
	movdqa		xmm0, xmm5

	; SHA2_P(36~39)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+90h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r36~r37, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w5.w4.w7.w6	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r38~r39, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(40~43)
	sha256msg1	xmm6, xmm7				; ...w12. : w11.w10.w9.w8
	movdqa		xmm3, xmm5				; xmm3 = ...w4
	palignr		xmm3, xmm4, 4			; xmm3 = w4.w3.w2.w1
	paddd		xmm6, xmm3				; w4.w3.w2.w1 + w11.w10.w9.w8
	sha256msg2	xmm6, xmm5				; w7.w6... : w11.w10.w9.w8
	movdqa		xmm0, xmm6

	; SHA2_P(40~43)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+0a0h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r40~r41, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w9.w8.w11.w10	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r42~r43, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(44~47)
	sha256msg1	xmm7, xmm4				; ...w0. : w15.w14.w13.w12
	movdqa		xmm3, xmm6				; xmm3 = ...w8
	palignr		xmm3, xmm5, 4			; xmm3 = w8.w7.w6.w5
	paddd		xmm7, xmm3				; w8.w7.w6.w5 + w15.w14.w13.w12
	sha256msg2	xmm7, xmm6				; w11.w10... : w15.w14.w13.w12
	movdqa		xmm0, xmm7

	; SHA2_P(44~47)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+0b0h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r44~r45, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w13.w12.w15.w14	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r46~r47, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(48~51)
	sha256msg1	xmm4, xmm5				; ...w4. : w3.w2.w1.w0
	movdqa		xmm3, xmm7				; xmm3 = ...w12
	palignr		xmm3, xmm6, 4			; xmm3 = w12.w11.w10.w9
	paddd		xmm4, xmm3				; w12.w11.w10.w9 + w3.w2.w1.w0
	sha256msg2	xmm4, xmm7				; w15.w14... : w3.w2.w1.w0
	movdqa		xmm0, xmm4

	; SHA2_P(48~51)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+0c0h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r48~r49, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w1.w0.w3.w2	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r50~r51, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(52~55)
	sha256msg1	xmm5, xmm6				; ...w8. : w7.w6.w5.w4
	movdqa		xmm3, xmm4				; xmm3 = ...w0
	palignr		xmm3, xmm7, 4			; xmm3 = w0.w15.w14.w13
	paddd		xmm5, xmm3				; w0.w15.w14.w13 + w7.w6.w5.w4
	sha256msg2	xmm5, xmm4				; w3.w2... : w7.w6.w5.w4
	movdqa		xmm0, xmm5

	; SHA2_P(52~55)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+0d0h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r52~r53, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w5.w4.w7.w6	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r54~r55, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(56~59)
	sha256msg1	xmm6, xmm7				; ...w12. : w11.w10.w9.w8
	movdqa		xmm3, xmm5				; xmm3 = ...w4
	palignr		xmm3, xmm4, 4			; xmm3 = w4.w3.w2.w1
	paddd		xmm6, xmm3				; w4.w3.w2.w1 + w11.w10.w9.w8
	sha256msg2	xmm6, xmm5				; w7.w6... : w11.w10.w9.w8
	movdqa		xmm0, xmm6

	; SHA2_P(56~59)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+0e0h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r56~r57, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w9.w8.w11.w10	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r58~r59, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	; SHA2_W(60~63)
	sha256msg1	xmm7, xmm4				; ...w0. : w15.w14.w13.w12
	movdqa		xmm3, xmm6				; xmm3 = ...w8
	palignr		xmm3, xmm5, 4			; xmm3 = w8.w7.w6.w5
	paddd		xmm7, xmm3				; w8.w7.w6.w5 + w15.w14.w13.w12
	sha256msg2	xmm7, xmm6				; w11.w10... : w15.w14.w13.w12
	movdqa		xmm0, xmm7

	; SHA2_P(60~63)
	; add next four raSha256K values
	movdqa		xmm3, [ebx+0f0h]
	paddd		xmm0, xmm3
	sha256rnds2	xmm2, xmm1, xmm0		; r60~r61, abef, cdgh
	pshufd		xmm0, xmm0, 4eh			; w13.w12.w15.w14	$0b01001110
	sha256rnds2	xmm1, xmm2, xmm0		; r62~r63, cdgh, abef

	;;;;;;;;;;;;;;;;;;;
	pxor		xmm3, xmm3
	pshufd		xmm0, xmm1, 1bh			; xmm0 = feba		$0b00011011
	punpckldq	xmm0, xmm3				; .b.a
	movdqu		xmm4, [eax]				; ctx[.b.a] += .b.a
	paddd		xmm4, xmm0
	movdqu		[eax], xmm4

	pshufd		xmm0, xmm1, 0b1h		; xmm0 = bafe		$0b10110001
	punpckldq	xmm0, xmm3				; .f.e
	movdqu		xmm4, [eax+20h]			; ctx[.f.e] += .f.e
	paddd		xmm4, xmm0
	movdqu		[eax+20h], xmm4

	pshufd		xmm0, xmm2, 1bh			; xmm0 = hgdc		$0b00011011
	punpckldq	xmm0, xmm3				; .d.c
	movdqu		xmm4, [eax+10h]			; ctx[.d.c] += .d.c
	paddd		xmm4, xmm0
	movdqu		[eax+10h], xmm4

	pshufd		xmm0, xmm2, 0b1h		; xmm0 = dchg		$0b10110001
	punpckldq	xmm0, xmm3				; .h.g
	movdqu		xmm4, [eax+30h]			; ctx[.h.g] += .h.g
	paddd		xmm4, xmm0
	movdqu		[eax+30h], xmm4

	;;;;;;;;;;;;;;;;;;;
	pop			edx
	pop			ecx
	pop			ebx
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
RaSha256Process_x86 ENDP


; void RaSha256CheckForInstructionSet( struct RaSha2Ctx *ctx )
RaSha256CheckForInstructionSet PROC
	push		ebp
	mov			ebp, esp
	push		eax
	push		ebx
	push		ecx		; (arg0) ctx
	push		edx

	; Look for CPUID.7.0.EBX[29]
	; EAX = 7, ECX = 0
	mov			eax, 7
	mov			ecx, 0
	cpuid

	bt			ebx, 29
	jnc			no_shae
	mov			ecx, ARG0				; (arg0) struct RaSha2Ctx *ctx
	mov			eax, RaSha256Process_x86
	mov			CTX_PROCESS, eax		; ctx->fnRaSha256Process
	
no_shae:
	pop			edx
	pop			ecx
	pop			ebx
	pop			eax
	pop			ebp
	ret

RaSha256CheckForInstructionSet ENDP

_TEXT ENDS

END
