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
                // remember to keep stack aligned!
                # already 16 aligned when ret from xor decoder
                # push with odd number to mimic being called
                push    rbp
                push    rdi
                push    rsi
                push    rbx
                push    r15
                sub     rsp, 0x28

                call    GetKernel32BaseAddr
                lea     rcx, [rip + ExitProcess]
                call    GetKernel32Proc
                mov     [rip + ExitProcessAddr], rax

# get xor_key_compressed (ends with @) from cmdline to rbp
#
        mov rax, gs:[0x60]
        mov rax, [rax+0x20]
        push rax
        mov cx, [rax+0x70]
        mov rax, [rax+0x78]
        movzx rcx, cx
        push rcx
        add rax, rcx
        sub rax, 34
        push rax
        mov cx, 16
        xor rbp, rbp
        xor rdx, rdx
        .convert_loop:
        mov dx, [rax]
        sub dx, '0'
        cmp dx, 9
        jle add_to_result
        sub dx, 7
        cmp dx, 15
        jle add_to_result
        sub dx, 32
        cmp dx, 15
        jg .quit
        add_to_result:
        test rdx, rdx
        jns .allow_add
        .quit:
        jmp     [rip + ExitProcessAddr]
        .allow_add:
        shl rbp, 4
        add rbp, rdx
        add rax, 2
        dec cx
        cmp cx, 0
        jne .convert_loop
        pop rdi
        pop rcx
        pop rdx
        sub cx, 36
        mov [rdx+0x70], cx
        xor eax, eax
        sub rdi, 2 // space
        mov ecx, 36
        rep stosb
# cmdline ends


                lea     rcx, [rip + VirtualAlloc]
                call    GetKernel32Proc

                // the memory after this image is free, to ensure those offsets are within 4 bytes
                lea     rcx, [rip + vp_base] // image base
                xor     rdx, rdx
                mov     edx, [rcx+0x3c] // e_lfanew
                add     edx, [rcx + rdx + 0x50] // image_size
                add     rcx, rdx
                add     rcx, 0x10000 // AllocationGranularity
                mov     rdx, IMM64(uncompressed_size)
                mov     r8, 0x3000
                mov     r9, 0x40
                call    rax
                mov     rdi, rax // start_of_uncompressed
                lea     rsi, [rip + start_of_compressed]

                add     rsp, 0x28
#
# restore shallow
#
                mov     rbx, rsi
                xor     rdx, rdx
                add     edx, IMM32(compressed_size)
                add     rbx, rdx
                xor     rcx, rcx
                restore_shallow_start:
                mov     rax, [rbx + rcx]
                or      [rsi + rcx], rax
                add     ecx, 8
                cmp     ecx, edx
                jb      restore_shallow_start
# shallow ends

#
# DEOBFUSCATE START
#
                xor     rcx, rcx
                xor_compressed_start:
                mov     rax, [rsi + rcx]
                xor     rax, rbp
                mov     [rsi + rcx], rax
                add     rcx, 8
                cmp     ecx, IMM32(compressed_size)
                jb      xor_compressed_start

# DEOBFUSCATE END
#

                sub     rsp, 0x28
                call    GetKernel32BaseAddr
                lea     rcx, [rip + VirtualProtect]
                call    GetKernel32Proc
                mov     [rip + VirtualProtectAddr], rax
                add     rsp, 0x28

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
                sub     rsp, 0x28

                lea     rcx, [rip + LoadLibraryA]
                call    GetKernel32Proc
                mov     r13, rax
                lea     rcx, [rip + GetProcAddress]
                call    GetKernel32Proc
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
                // no need to restore registers
                //      rcx contains garbage -> garbage return code
                jmp     [rip + ExitProcessAddr]
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
                pop     rbx
                pop     rsi
                pop     rdi
                pop     rbp

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
                push    rcx // 16 aligned when ret from xor decoder, mimic being called
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

section         WINAPI
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
	lea	r8, [rip + kernel32BaseAddr]
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
        lea	r9, [rip + kernel32]
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
	lea	r8, [rip + kernel32BaseAddr]
	mov	[r8], rax
LN3_GetKernel3:
//; Line 59
	add	rsp, 536				//; 00000218H
	ret	0
// GetKernel32BaseAddr ENDP
// section         GET_KERNEL32_PROC


LoadLibraryA:
        .asciz "LoadLibraryA"
GetProcAddress:
        .asciz "GetProcAddress"
ExitProcess:
        .asciz "ExitProcess"
VirtualAlloc:
        .asciz "VirtualAlloc"
VirtualProtect:
        .asciz "VirtualProtect"
kernel32:
        .short 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0
kernel32BaseAddr:
        .quad 0
VirtualProtectAddr:
        .quad 0
ExitProcessAddr:
        .quad 0

section UPX_STUB
        push    rax
        test    rax, rax // use rax for comouflage
        jz      alternative
        lea     rax, [rsp - 0x38]
        alternative:
        lea     rax, [rsp - 0x48]
        xor     rdx, rdx
        mov     dl, al
        shl     dl, 4
        shr     dl, 1 // 0x40/@
        push    rdx
        sub     rsp, 0x30
section ARGC
        xor     rdx, rdx
        mov     dx, [rip+argc]
        dec     dx
        test    dx, dx
        jz      out
section ARGV
        mov     rax, [rip+argv]
section CMD_READ_CLI
        mov     rax, [rax + rdx*8]
section CMD_CALL_GUI
        call    rax
section CMD_READ_GUI
        mov     rax, [rax]
section CMD_CHAR
        cmd_char:
        mov     dl, [rax]
        test    dl, dl
        jz      stub_main
        mov     cl, dl
        inc     rax
        jmp     cmd_char
section CMD_WCHAR
        cmd_wchar:
        mov     dx, [rax]
        test    dx, dx
        jz      stub_main
        mov     cx, dx
        add     rax, 2
        jmp     cmd_wchar
section UPX_STUB_MAIN01
        stub_main:
        mov     rdx, [rsp + 0x30]
        cmp     dl, cl // @
        jnz     out
        xor     rax, rax
section UPX_STUB_SMALL
        mov     ax, IMM16(loader_decoder_offset)
section UPX_STUB_LARGE
        mov     eax, IMM32(loader_decoder_offset)
section UPX_STUB_MAIN02
        shl     rax, 8
        lea     rcx, [rip+data_random]
        add     rcx, rax
        mov     [rsp + rdx], rcx // rsp+40: ret
out:
        mov     rax, [rsp+0x38]
        add     rsp, 0x40
        ret

section LOADER_DECODER
# deobfuscate the loader
        lea     rax, [rip + loader_start]
        push    rax
        lea     rbx, [rip + loader_end]
        mov     cl, IMM8(xor_key_loader)
        mov     ch, cl
        not     ch
        decode_loader_loop:
        mov     dl, [rax]
        mov     dh, dl
        not     dh
        and     dh, cl
        and     dl, ch
        or      dl, dh
        mov     [rax], dl
        inc     rax
        cmp     rax, rbx
        jb      SHORT(decode_loader_loop)
        ret
/* vim:set ts=8 sw=8 et: */
