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

section         PREFIX
        jmp START
                mov     rdx, IMM64(xor_key_loader)
                lea     rsi, [rip + START]
                lea     rdi, [rip + DATA1_END]
                xor_loader_start:
                mov     rax, [rsi]
                xor     rax, rdx
                mov     [rsi], rax
                add     rsi, 8
                cmp     rsi, rdi
                jb      xor_loader_start

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
                push    rbp
                push    rdi
                push    rsi
                push    rbx
                push    r15
                //; remember to keep stack aligned!
                lea     rsi, [rip + start_of_compressed]
                lea     rcx, [rip + VirtualAlloc]
                call    get_kernel32_proc

                lea     rcx, [rip + image_size] // the memory after this image is free, to ensure those offsets are within 4 bytes
                mov     rdx, IMM64(uncompressed_size)
                mov     r8, 0x3000
                mov     r9, 0x40
                call    rax
                mov     rdi, rax // start_of_uncompressed

#
# DEOBFUSCATE START
#
                mov     rdx, IMM64(xor_key_compressed)
                xor     rcx, rcx
                xor_compressed_start:
                mov     rax, [rsi + rcx]
                xor     rax, rdx
                mov     [rsi + rcx], rax
                add     rcx, 8
                cmp     ecx, IMM32(compressed_size)
                jb      xor_compressed_start

# DEOBFUSCATE END
#


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
                sub     rsp, 0x20 // 'push r15' already balanced

                lea     rcx, [rip + LoadLibraryA]
                call    get_kernel32_proc
                mov     r13, rax
                lea     rcx, [rip + GetProcAddress]
                call    get_kernel32_proc
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
                call    get_kernel32_proc
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
                xor     rcx, rcx // is_32bits
                lea     rax, [rip + vp_base]
                mov     r9, rsi
                sub     r9, rax // (uncompressed base - image base)

reloc_main:
                xor     eax, eax
                mov     al, [rdi]
                inc     rdi
                or      eax, eax
                jz      SHORT(reloc_endx)
                cmp     al, 0x7f
                ja      reloc_fx
reloc_add:
                or      cl, cl
                jnz     SHORT(reloc_32)
                add     rbx, rax
                mov     rax, [rbx]
                bswap   rax
                add     rax, rsi
                mov     [rbx], rax
                jmp     reloc_main
                reloc_32: // relocate RVA
                add     rbx, rax
                mov     eax, [rbx]
                bswap   eax
                add     eax, r9d
                mov     [rbx], eax
                jmp     reloc_main
reloc_fx:
                mov     cl, al
                and     cl, 0x40
                cmp     cl, ch
                je      SHORT(same_type)
                mov     ch, cl
                lea     rbx, [rsi - 4] // reset the base address
                same_type:
                and     al, 0x3F
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
                lea     rdi, [rip + vp_base]
                mov     ebx, IMM32(vp_size)     // 0x1000 or 0x2000

                push    rax                     // provide 8 bytes stack
                mov     r9, rsp
// FIXME        push    4; pop     r8
                mov     r8d, 4                  // PAGE_READWRITE
                mov     rdx, rbx                // size
                mov     rcx, rdi                // address

                sub     rsp, 0x20
                call    [rip + VirtualProtectAddr]

                mov     rcx, rsi
                sub     rcx, rdi // add to (uncompressed base - image base)
                mov     rdx, IMM64(uncompressed_size)
                add     rdx, rcx
                lea     rax, [rdi + dir_table]
                mov     [rax + -0x38], edx // new image size, FindResource will check this
                xor     rdx, rdx
                mov     edx, IMM32(res_vaddr)
                add     edx, ecx
                mov     [rax + 8*2], edx
                mov     [rax + 8*2 + 4], IMM32(res_size)
                mov     edx, IMM32(exc_vaddr)
                add     edx, ecx
                mov     [rax + 8*3], edx
                mov     [rax + 8*3 + 4], IMM32(exc_size)

                lea     r9, [rsp + 0x20]
                movq    r8, [r9]                // original protection
                mov     rdx, rbx
                mov     rcx, rdi

                call    [rip + VirtualProtectAddr]
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
                mov     r9, rsi // uncompressed start
                pop     r15
                pop     rbp
                pop     rdi
                pop     rsi
                pop     rbx

                push    rcx // align stack

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
                xor     rcx, rcx
                mov     ecx, IMM32(original_entry)
                add     r9, rcx
                jmp     r9

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

section         DATA1
VirtualAlloc:
        .asciz "VirtualAlloc"
LoadLibraryA:
        .asciz "LoadLibraryA"
GetProcAddress:
        .asciz "GetProcAddress"
ExitProcess:
        .asciz "ExitProcess"
.global DATA1_END // keep in the symbol table
DATA1_END:
        .quad 0         // align for xor

section         DATA2
.global kernel32, VirtualProtect, kernel32BaseAddr, VirtualProtectAddr, DATA2_END
kernel32:
        .short 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0
VirtualProtect:
        .asciz "VirtualProtect"
kernel32BaseAddr:
        .quad 0
VirtualProtectAddr:
        .quad 0
DATA2_END:
        .quad 0         // align for xor

section         GET_KERNEL32_PROC
                // mimic mainCRTStartup
                sub     rsp, 0x28
                call    dummpy_func
                add     rsp, 0x28
                // jmp     unprotect_bootstrap_start
                jmp unprotect_bootstrap_end
#
# UNPROTECT START
#

unprotect_bootstrap_start:
        // initial protect value
                sub     rcx, r8 // they are equal (need verify in all OS)
                inc     ecx
                xchg    esi, ecx
                ror     esi, 26  // 0x40

                mov     rdx, IMM64(xor_key_loader)
                lea     rcx, [rip + data2]
                lea     r8, [rcx + data2_len]
                xor_data2_start:
                mov     rax, [rcx]
                xor     rax, rdx
                mov     [rcx], rax
                add     rcx, 8
                cmp     rcx, r8
                jb      xor_data2_start
unprotect_bootstrap_end:
                call    GetKernel32BaseAddr

                lea     rcx, [rip + virtual_protect]
                call    GetKernel32Proc
                mov     [rip + virtual_protect_addr], rax

                lea     rax, [rip + upx_start]
                jmp     rax
#
# UNPROTECT END
#

.global GetKernel32Proc
GetKernel32Proc:
//; File d:\tmp\upx\src\stub\src\GetKernel32Proc.c
//; Line 61
LN25:
	mov	rax, rsp
	mov	QWORD PTR [rax+8], rbx
	mov	QWORD PTR [rax+16], rbp
	mov	QWORD PTR [rax+24], rsi
	mov	QWORD PTR [rax+32], rdi
	push	r14
//; Line 62
	lea	r8, [rip + kernel32_base_addr]
	mov	r8, [r8]
	xor	edx, edx
	mov	rbp, rcx
	test	r8, r8
	jne	SHORT LN8_GetKernel3
//; Line 63
	xor	eax, eax
	jmp	SHORT LN1_GetKernel3
LN8_GetKernel3:
//; Line 68
	movsxd	rax, DWORD PTR [r8+60]
//; Line 87
	mov	r9d, edx
	mov	ecx, DWORD PTR [rax+r8+136]
	add	rcx, r8
	mov	edi, DWORD PTR [rcx+28]
	mov	r10d, DWORD PTR [rcx+32]
	add	rdi, r8
	mov	esi, DWORD PTR [rcx+36]
	add	r10, r8
	mov	r14d, DWORD PTR [rcx+24]
	add	rsi, r8
	test	r14d, r14d
	je	SHORT LN6_GetKernel3
LL7_GetKernel3:
//; Line 88
	mov	eax, DWORD PTR [r10]
//; Line 89
	mov	rbx, rbp
	add	rax, r8
	sub	rbx, rax
LL22_GetKernel3:
	movzx	ecx, BYTE PTR [rax]
	movzx	r11d, BYTE PTR [rax+rbx]
	sub	ecx, r11d
	jne	SHORT LN23_GetKernel3
	inc	rax
	test	r11d, r11d
	jne	SHORT LL22_GetKernel3
LN23_GetKernel3:
	test	ecx, ecx
	je	SHORT LN15_GetKernel3
//; Line 87
	inc	r9d
	add	r10, 4
	cmp	r9d, r14d
	jb	SHORT LL7_GetKernel3
//; Line 89
	jmp	SHORT LN6_GetKernel3
LN15_GetKernel3:
//; Line 90
	mov	eax, r9d
	movzx	ecx, WORD PTR [rsi+rax*2]
	mov	edx, DWORD PTR [rdi+rcx*4]
	add	rdx, r8
LN6_GetKernel3:
//; Line 95
	mov	rax, rdx
LN1_GetKernel3:
//; Line 96
	mov	rbx, QWORD PTR [rsp+16]
	mov	rbp, QWORD PTR [rsp+24]
	mov	rsi, QWORD PTR [rsp+32]
	mov	rdi, QWORD PTR [rsp+40]
	pop	r14
	ret	0
// GetKernel32Proc ENDP

GetKernel32BaseAddr:
//; File d:\tmp\upx\src\stub\src\GetKernel32Proc.c
//; Line 24
LN26:
	sub	rsp, 536				//; 00000218H
//; Line 29
	mov	rax, QWORD PTR gs:96
//; Line 43
	xor	r10d, r10d
	mov	rcx, QWORD PTR [rax+24]
	mov	rdx, QWORD PTR [rcx+16]
	jmp	SHORT LN22_GetKernel3
LL2_GetKernel3:
//; Line 45
	mov	r8, QWORD PTR [rdx+96]
	mov	r9b, r10b
	jmp	SHORT LN24_GetKernel3
LL6_GetKernel3:
//; Line 46
	lea	eax, DWORD PTR [rcx-65]
	cmp	ax, 25
	ja	SHORT LN7_GetKernel3
//; Line 47
	xor	cx, 32					//; 00000020H
	mov	WORD PTR [r8], cx
LN7_GetKernel3:
//; Line 45
	movsx	rax, r9b
	inc	r9b
	add	r8, 2
	mov	WORD PTR [rsp+rax*2], cx
LN24_GetKernel3:
	movzx	ecx, WORD PTR [r8]
	test	cx, cx
	jne	SHORT LL6_GetKernel3
//; Line 52
	movsx	rax, r9b
//; Line 53
        lea	r9, [rip + kernel_32]
	mov	WORD PTR [rsp+rax*2], r10w
	lea	rax, QWORD PTR [rsp]
	sub	r9, rax
LL20_GetKernel3:
	movzx	ecx, WORD PTR [rax]
	movzx	r8d, WORD PTR [rax+r9]
	sub	ecx, r8d
	jne	SHORT LN21_GetKernel3
	add	rax, 2
	test	r8d, r8d
	jne	SHORT LL20_GetKernel3
LN21_GetKernel3:
	test	ecx, ecx
	je	SHORT LN13_GetKernel3
//; Line 57
	mov	rdx, QWORD PTR [rdx+16]
	sub	rdx, 16
LN22_GetKernel3:
//; Line 43
	cmp	QWORD PTR [rdx+48], r10
	jne	SHORT LL2_GetKernel3
//; Line 53
	jmp	SHORT LN3_GetKernel3
LN13_GetKernel3:
//; Line 54
	mov	rax, QWORD PTR [rdx+48]
	lea	r8, [rip + kernel32_base_addr]
	mov	[r8], rax
LN3_GetKernel3:
//; Line 59
	add	rsp, 536				//; 00000218H
dummpy_func:
	ret	0
// GetKernel32BaseAddr ENDP
// section         GET_KERNEL32_PROC

/* vim:set ts=8 sw=8 et: */
