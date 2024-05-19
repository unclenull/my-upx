/*
;  AMD64-win64.pe.S -- loader & decompressor for the w64/pe32+ format
;
;  This file is part of the UPX executable compressor.
;
;  Copyright (C) 1996-2024 Markus Franz Xaver Johannes Oberhumer
;  Copyright (C) 1996-2024 Laszlo Molnar
;  All Rights Reserved.
;
;  UPX and the UCL library are free software; you can redistribute them
;  and/or modify them under the terms of the GNU General Public License as
;  published by the Free Software Foundation; either version 2 of
;  the License, or (at your option) any later version.
;
;  This program is distributed in the hope that it will be useful,
;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  GNU General Public License for more details.
;
;  You should have received a copy of the GNU General Public License
;  along with this program; see the file COPYING.
;  If not, write to the Free Software Foundation, Inc.,
;  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
;
;  Markus F.X.J. Oberhumer              Laszlo Molnar
;  <markus@oberhumer.com>               <ezerotven+github@gmail.com>
;
;---------------------------------------------------------------------
;
; 64 bit modifications (C) 2010 Stefan Widmann
;
; Major changes when porting 32 bit code to 64 bit:
;  - there are no pusha/popa instructions
;  - since we cannot use pusha/popa, we save rbx, rsi, rdi and rbp instead
;  - inc <reg> are now being encoded in 2 byte instructions
;  - functions use fast call calling convention (parameters are passed in registers)
;    rcx, rdx,  r8, r9
;  - caller is responsible for stack allocation for callee
;  - caller cleans up stack
;  - caller must keep the stack 16 byte aligned, 32 bytes shadow space on stack
; For more information about the 64 bit calling convention see http://blogs.msdn.com/oldnewthing/archive/2004/01/14/58579.aspx
*/

#include "arch/amd64/macros.S"

#define         IMM8(value) byte ptr 0; \
                .reloc . - 1, R_X86_64_8, value

#define         IMM16(value) word ptr (1<<15); \
                .reloc . - 2, R_X86_64_16, (1<<15) + value

#define         IMM32(value) dword ptr (1<<31); \
                .reloc . - 4, R_X86_64_32, (1<<31) + value

#define         IMM64(value) qword ptr (1<<63); \
                .reloc . - 8, R_X86_64_64, (1<<63) + value

#define         SHORT(label) . + 1; .reloc . - 1, R_X86_64_PC8, label

//; debugging is not too user friendly under wine:
//; by adding the "DEBUG" macro into the code
//; an exception will be raised, and a register dump is printed
//; WINEDEBUG=trace+seh wine x.exe &> x.debug
#define         DEBUG           movb [0], 0

.intel_syntax noprefix

// =============
// ============= ENTRY POINT
// =============

section         START
section         PEISDLL0
                mov     [rsp + 8], rcx
                mov     [rsp + 0x10], rdx
                mov     [rsp + 0x18], r8
section         PEISEFI0
                push     rcx
                push     rdx

section         PEISDLL1
                cmp     dl, 1
                jnz     reloc_end_jmp
section         PEMAIN01
                //; remember to keep stack aligned!
                lea     rsi, [rip + start_of_compressed]
                lea     rdi, [rsi + start_of_uncompressed]
                push    rbp
                push    rdi
                push    rsi
                push    rbx
                push    r15

#
# DEOBFUSCATE START
#
                mov     rdx, IMM64(xor_key)
                xor     rcx, rcx
                xor_start:
                mov     rax, [rsi + rcx]
                xor     rax, rdx
                mov     [rsi + rcx], rax
                add     rcx, 8
                cmp     ecx, IMM32(compressed_size)
                jb      xor_start
#
# DEOBFUSCATE END
#


section         PEICONS1
                incw    [rdi + icon_offset]
section         PEICONS2
                add     [rdi + icon_offset], IMM16(icon_delta)
section         PETLSHAK
                lea     rax, [rdi + tls_address]
                push    [rax]   // save the TLS index
                mov     [rax],  IMM32(tls_value) // restore compressed data overwritten by the TLS index
                push    rax

section         PEMAIN02
                push    rdi
section         PEMAIN03

// =============
// ============= DECOMPRESSION
// =============

.att_syntax
section         NRV_HEAD
/* Working registers */
#define off  %eax  /* XXX: 2GB */
#define len  %ecx  /* XXX: 2GB */
#define lenq %rcx
#define bits %ebx
#define displ %ebp
#define dispq %rbp

        xor bits,bits  // empty; force refill
        xor len,len  // create loop invariant
        orq $(~0),dispq  // -1: initial displacement
        call setup  // push &getbit [TUNED]
ra_setup:

#define jnextb0np jnextb0yp
#define jnextb0yp GETBITp; jnc
#define jnextb1np jnextb1yp
#define jnextb1yp GETBITp; jc
#define GETBITp \
        addl bits,bits; jnz 0f; \
        movl (%rsi),bits; subq $-4,%rsi; \
        adcl bits,bits; movb (%rsi),%dl; \
0:
/* Same, but without prefetch (not useful for length of match.) */
#define jnextb0n jnextb0y
#define jnextb0y GETBIT; jnc
#define jnextb1n jnextb1y
#define jnextb1y GETBIT; jc
#define GETBIT \
        addl bits,bits; jnz 0f; \
        movl (%rsi),bits; subq $-4,%rsi; \
        adcl bits,bits; \
0:

/* rotate next bit into bottom bit of reg */
#define getnextbp(reg) call *%r11; adcl reg,reg
#define getnextb(reg)  getnextbp(reg)


getbit:
        addl bits,bits; jz refill  // Carry= next bit
        rep; ret
refill:
        movl (%rsi),bits; subq $-4,%rsi  // next 32 bits; set Carry
        adcl bits,bits  // LSB= 1 (CarryIn); CarryOut= next bit
        movb (%rsi),%dl  // speculate: literal, or bottom 8 bits of offset
        rep; ret

copy:  // In: len, %rdi, dispq;  Out: 0==len, %rdi, dispq;  trashes %rax, %rdx
        leaq (%rdi,dispq),%rax; cmpl $5,len  // <=3 is forced
        movb (%rax),%dl; jbe copy1  // <=5 for better branch predict
        cmpq $-4,dispq;   ja  copy1  // 4-byte chunks would overlap
        subl $4,len  // adjust for termination cases
copy4:
        movl (%rax),%edx; addq $4,      %rax; subl $4,len
        movl %edx,(%rdi); leaq  4(%rdi),%rdi; jnc copy4
        addl $4,len; movb (%rax),%dl; jz copy0
copy1:
        incq %rax; movb %dl,(%rdi); subl $1,len
                   movb (%rax),%dl
        leaq 1(%rdi),%rdi;          jnz copy1
copy0:
        rep; ret

setup:
        cld
        pop %r11  // addq $ getbit - ra_setup,%r11  # &getbit

#define NO_METHOD_CHECK

section         NRV2B
#define eof eofb
#include "arch/amd64/nrv2b_d.S"
eofb:

section         NRV2D
#undef eof
#define eof eofd
#include "arch/amd64/nrv2d_d.S"
eofd:

section         NRV2E
#undef eof
#define eof eofe
#include "arch/amd64/nrv2e_d.S"
eofe:

#undef eof
#undef len
.intel_syntax noprefix
section         LZMA_HEAD
                mov     eax, IMM32(lzma_u_len)
                push    rax
                mov     rcx, rsp
                mov     rdx, rdi
                mov     rdi, rsi
                mov     esi, IMM32(lzma_c_len)

.att_syntax
#define NO_RED_ZONE
#include "arch/amd64/regs.h"
#include "arch/amd64/lzma_d.S"

.intel_syntax noprefix
section         LZMA_TAIL
                leave
                pop     rax
// =============
section         PEMAIN10
                pop     rsi             // load vaddr

section         PETLSHAK2               // restore the TLS index
                pop     rdi
                pop     rax
                mov     [rdi], eax

// =============
// ============= FILTERS
// =============

section         PECTTPOS
                lea     rdi, [rsi + filter_buffer_start]
section         PECTTNUL
                mov     rdi, rsi

section         PEFILTER49
                push    rsi
                mov     rdi, rsi
                mov     rsi, offset filter_length
                mov     dl, IMM8(filter_cto)
.att_syntax
#include "arch/amd64/bxx.S"
.intel_syntax noprefix
                pop     rsi

// =============
// ============= IMPORTS
// =============

section PEIMPORT
                lea     rdi, [rsi + compressed_imports]
                mov     r15, rdi
                xor     rax, rax
                mov     ax, [rdi]
                add     rdi, rax
                sub     rsp, 0x20

                lea     rcx, [rip + LoadLibraryA]
                call    GetKernel32ProcAddr
                mov     r13, rax
                lea     rcx, [rip + GetProcAddress]
                call    GetKernel32ProcAddr
                mov     r14, rax
next_dll:
                mov     eax, [rdi]
                or      eax, eax
                jz      SHORT(imports_done)
                mov     ebx, [rdi + 4]    // iat
                lea     rcx, [rax + r15]
                add     rbx, rsi
                add     rdi, 8

                call    r13

                xchg    rax, rbp
next_func:
                mov     al, [rdi]
                inc     rdi
                or      al, al
                jz      next_dll
section         PEIBYORD
                jns     SHORT(byname)
section         PEK32ORD
                jpe     not_kernel32
                mov     eax, [rdi]
                add     rdi, 4
                mov     rax, [rax + rsi + kernel32_ordinals]
                jmp     SHORT(next_imp)
not_kernel32:
section         PEIMORD1
                movzx   rdx, word ptr [rdi]
                add     rdi, 2
                jmp     SHORT(first_imp)

byname:
section         PEIMPOR2
                mov     rcx, rdi        // something > 0
                mov     rdx, rdi
                dec     eax
                repne
                scasb
first_imp:
                mov     rcx, rbp

                call    r14

#if 1
;// FIXME: is this error handling really needed?
                or      rax, rax
                jz      imp_failed
#endif
next_imp:
                mov     [rbx], rax
                add     rbx, 8
                jmp     SHORT(next_func)
imp_failed:
section         PEIERDLL
                add     rsp, 0x20
                pop     r15
                pop     rbx
                pop     rsi
                pop     rdi
                pop     rbp
                xor     eax, eax
                ret

section         PEIEREXE
                add     rsp, 0x28
                //      rcx contains garbage -> garbage return code
                lea     rcx, [rip + ExitProcess]
                call    GetKernel32ProcAddr
                jmp     rax
section         PEIMDONE
imports_done:
                add     rsp, 0x28

// =============
// ============= RELOCATION
// =============

section         PERELOC1
                lea     rdi, [rsi + start_of_relocs]
section         PERELOC2
                add     rdi, 4
section         PERELOC3
                lea     rbx, [rsi - 4]
reloc_main:
                xor     eax, eax
                mov     al, [rdi]
                inc     rdi
                or      eax, eax
                jz      SHORT(reloc_endx)
                cmp     al, 0xEF
                ja      reloc_fx
reloc_add:
                add     rbx, rax
                mov     rax, [rbx]
                bswap   rax
                add     rax, rsi
                mov     [rbx], rax
                jmp     reloc_main
reloc_fx:
                and     al, 0x0F
                shl     eax, 16
                mov     ax, [rdi]
                add     rdi, 2
section         REL64BIG
                or      eax, eax
                jnz     SHORT(reloc_add)
                mov     eax, [rdi]
                add     rdi, 4
section         RELOC64J
                jmp     SHORT(reloc_add)
reloc_endx:


// =============

// FIXME: depends on that in PERELOC1 rdi is set!!
section         PERLOHI0
                xchg    rdi, rsi
                lea     rcx, [rdi + reloc_delt]

section         PERELLO0
                jmp     1f
rello0:
                add     [rdi + rax], cx
1:
                lodsd
                or      eax, eax
                jnz     rello0

// =============

section         PERELHI0
                shr     ecx, 16
                jmp     1f
relhi0:
                add     [rdi + rax], cx
1:
                lodsd
                or      eax, eax
                jnz     relhi0

// =============
section         PEDEPHAK
                lea     rcx, [rip + VirtualProtect]
                call    GetKernel32ProcAddr
                mov     rbp, rax
                lea     rdi, [rsi + vp_base]
                mov     ebx, IMM32(vp_size)     // 0x1000 or 0x2000

                push    rax                     // provide 8 bytes stack
                mov     r9, rsp
// FIXME        push    4; pop     r8
                mov     r8d, 4                  // PAGE_READWRITE
                mov     rdx, rbx                // size
                mov     rcx, rdi                // address

                sub     rsp, 0x20
                call    rbp                     // VirtualProtect

                lea     rax, [rdi + swri]
                andb    [rax], 0x7f             // marks UPX0 non writeable
                andb    [rax + 0x28], 0x7f      // marks UPX1 non writeable

                lea     rax, [rdi + res_dir]
                mov     [rax], IMM32(res_vaddr)
                add     rax, 4
                mov     [rax], IMM32(res_size)

                lea     r9, [rsp + 0x20]
                movq    r8, [r9]                // original protection
                mov     rdx, rbx
                mov     rcx, rdi

                call    rbp
                add     rsp, 0x28

// =============
// ============= TLS callback support part 1
// =============

section         PETLSC
                movb    [rip + PETLSC2], 0xfc   // "cld" instead of "ret"
                lea     rcx, [rsi + tls_module_base] // module base
                push    1                       // DLL_PROCESS_ATTACH
                pop     rdx
                xor     r8, r8                  // 0 - reserved

                push    rax                     // align stack
                call    PETLSC2
                pop     rax

// ============= Cleanup

section         PEMAIN20
                pop     rbp
                pop     rdi
                pop     rsi
                pop     rbx

// clear the dirty stack
.macro          clearstack128  tmp_reg
                .local   loop
                lea     \tmp_reg, [rsp - 128]
loop:
                push    0
                cmp     rsp, \tmp_reg
                jnz     loop
                sub     rsp, -128
.endm

section         CLEARSTACK
                clearstack128 rax

section         PEMAIN21
reloc_end_jmp:

section         PEISDLL9
                mov     r8, [rsp + 0x18]
                mov     rdx, [rsp + 0x10]
                mov     rcx, [rsp + 8]
section         PEISEFI9
                pop     rdx
                pop     rcx

section         PERETURN
                push    1
                pop     rax
                ret
section         PEDOJUMP
                jmp     original_entry

// =============
// ============= TLS callback support part 2
// =============

// this is the new TLS callback handler
// it calls the original callbacks ONLY after the decompression is done

section         PETLSC2         // TLS_CALLBACK(hModule, reason, reserved)
                ret             // this ret gets overwritten with cld by PETLSC
                push    rsi
                lea     rsi, [rip + tls_callbacks_ptr]
walk_tlsc_chain2:
                lodsq
                test    rax, rax
                jz      done_callbacks

                push    rcx
                push    rdx
                push    r8

                sub     rsp, 0x28
                call    rax
                add     rsp, 0x28

                pop     r8
                pop     rdx
                pop     rcx

                jmp     walk_tlsc_chain2
done_callbacks:
                pop     rsi
                ret


section         GET_KERNEL32_PROC
GetKernel32ProcAddr:
//; File D:\tmp\upx\src\stub\src\GetKernel32Proc.c
//; Line 26
LN48:
	mov	rax, rsp
	mov	QWORD PTR [rax+8], rbx
	mov	QWORD PTR [rax+16], rbp
	mov	QWORD PTR [rax+24], rsi
	mov	QWORD PTR [rax+32], rdi
	push	r14
	sub	rsp, 528				//; 00000210H
//; Line 31
	mov	rax, QWORD PTR gs:96
	mov	r14, rcx
//; Line 40
	mov	rdx, QWORD PTR [rax+24]
	mov	r8, QWORD PTR [rdx+16]
//; Line 46
	xor	edx, edx
	jmp	SHORT LN44_GetProc
LL2_GetProc:
//; Line 48
	mov	r9, QWORD PTR [r8+96]
	mov	r10b, dl
	jmp	SHORT LN46_GetProc
LL6_GetProc:
//; Line 49
	lea	eax, DWORD PTR [rcx-65]
	cmp	ax, 25
	ja	SHORT LN13_GetProc
//; Line 50
	xor	cx, 32					//; 00000020H
	mov	WORD PTR [r9], cx
LN13_GetProc:
//; Line 48
	movsx	rax, r10b
	inc	r10b
	add	r9, 2
	mov	WORD PTR [rsp+rax*2], cx
LN46_GetProc:
	movzx	ecx, WORD PTR [r9]
	test	cx, cx
	jne	SHORT LL6_GetProc
//; Line 55
	movsx	rax, r10b
//; Line 56
        lea	r10, [rip + kernel32]
	mov	WORD PTR [rsp+rax*2], dx
	lea	rax, QWORD PTR [rsp]
	sub	r10, rax
LL42_GetProc:
	movzx	ecx, WORD PTR [rax]
	movzx	r9d, WORD PTR [rax+r10]
	sub	ecx, r9d
	jne	SHORT LN43_GetProc
	add	rax, 2
	test	r9d, r9d
	jne	SHORT LL42_GetProc
LN43_GetProc:
	test	ecx, ecx
	je	SHORT LN24_GetProc
//; Line 60
	mov	r8, QWORD PTR [r8+16]
	sub	r8, 16
LN44_GetProc:
//; Line 46
	cmp	QWORD PTR [r8+48], rdx
	jne	SHORT LL2_GetProc
LN39_GetProc:
//; Line 64
	xor	eax, eax
LN1_GetProc:
//; Line 97
	lea	r11, QWORD PTR [rsp+528]
	mov	rbx, QWORD PTR [r11+16]
	mov	rbp, QWORD PTR [r11+24]
	mov	rsi, QWORD PTR [r11+32]
	mov	rdi, QWORD PTR [r11+40]
	mov	rsp, r11
	pop	r14
	ret	0
LN24_GetProc:
//; Line 57
	mov	r9, QWORD PTR [r8+48]
//; Line 63
	test	r9, r9
	je	SHORT LN39_GetProc
//; Line 69
	movsxd	rax, DWORD PTR [r9+60]
//; Line 88
	mov	r8d, edx
	mov	ecx, DWORD PTR [rax+r9+136]
	add	rcx, r9
	mov	edi, DWORD PTR [rcx+28]
	mov	r10d, DWORD PTR [rcx+32]
	add	rdi, r9
	mov	esi, DWORD PTR [rcx+36]
	add	r10, r9
	mov	ebp, DWORD PTR [rcx+24]
	add	rsi, r9
	test	ebp, ebp
	je	SHORT LN11_GetProc
LL12_GetProc:
//; Line 89
	mov	eax, DWORD PTR [r10]
//; Line 90
	mov	rbx, r14
	add	rax, r9
	sub	rbx, rax
LL40_GetProc:
	movzx	ecx, BYTE PTR [rax]
	movzx	r11d, BYTE PTR [rax+rbx]
	sub	ecx, r11d
	jne	SHORT LN41_GetProc
	inc	rax
	test	r11d, r11d
	jne	SHORT LL40_GetProc
LN41_GetProc:
	test	ecx, ecx
	je	SHORT LN26_GetProc
//; Line 88
	inc	r8d
	add	r10, 4
	cmp	r8d, ebp
	jb	SHORT LL12_GetProc
//; Line 90
	jmp	SHORT LN11_GetProc
LN26_GetProc:
//; Line 91
	mov	eax, r8d
	movzx	ecx, WORD PTR [rsi+rax*2]
	mov	edx, DWORD PTR [rdi+rcx*4]
	add	rdx, r9
LN11_GetProc:
//; Line 96
	mov	rax, rdx
	jmp	LN1_GetProc
// GetKernel32ProcAddr end

kernel32:
        .short 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0
LoadLibraryA:
        .asciz "LoadLibraryA"
GetProcAddress:
        .asciz "GetProcAddress"
ExitProcess:
        .asciz "ExitProcess"
VirtualProtect:
        .asciz "VirtualProtect"

/* vim:set ts=8 sw=8 et: */
