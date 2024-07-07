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
                add     rsp, 0x28
#
# get xor_key_pe from cmdline to r8
#
        mov rax, gs:[0x60]
        mov rax, [rax+0x20]
        push rax
        mov cx, [rax+0x70]
        mov rax, [rax+0x78]
        movzx rcx, cx
        push rcx
        add rax, rcx
        sub rax, 32
        push rax
        mov cx, 16
        xor r8, r8
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
        shl r8, 4
        add r8, rdx
        add rax, 2
        dec cx
        cmp cx, 0
        jne .convert_loop
        pop rdi
        pop rcx
        pop rdx
        sub cx, 34
        mov [rdx+0x70], cx
        xor eax, eax
        sub rdi, 2
        mov ecx, 34
        rep stosb

#
# DEOBFUSCATE START
#
                lea     rsi, [rip + start_of_pe]
                mov     rdi, rsi
                lea r15, [rip + xor_zero_offsets]
                mov rbx, r8
                and rbx, 63
                or rbx, 1
                xor r9, r9
                dec r9
                inc r9b // 0xff...00
                xor     r11, r11

                xor_pe_loop:
                mov     rdx, [rsi + r11]
                test    rdx, rdx
                jnz     .xor_pe_loop_continue
                lea     rcx, [r11 + 8]
                cmp     [r15], ecx // one zero byte is the result of xor
                jae      skip_xor_pe

                .xor_pe_loop_continue:
                mov cl, bl
                ror rdx, cl
                mov r10, rdx
                xor r10, r8
                xor rcx, rcx
                // loop over each byte
                .xor_pe_byte_loop:
                mov rax, rdx
                shr rax, cl
                and al, 0xFF

                // if the byte is zero and offset not in the zeros table, clear it
                test al, al
                jnz .xor_pe_byte_loop_end
                mov rax, rcx
                shr rax, 3
                add rax, r11
                cmp eax, [r15]
                jz .xor_pe_byte_loop_skip

                // clear
                mov rax, r9
                rol rax, cl
                and r10, rax
                jmp .xor_pe_byte_loop_end

                .xor_pe_byte_loop_skip:
                add r15, 4

                .xor_pe_byte_loop_end:
                // increment counter and check if we've processed all bytes
                add cx, 8
                cmp cx, 64
                jl .xor_pe_byte_loop

                mov     [rsi + r11], r10

                skip_xor_pe:
                add     r11, 8
                cmp     r11d, IMM32(pe_size)
                jb      xor_pe_loop

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

section         PETLSHAK2               // restore the TLS index
                pop     rdi
                pop     rax
                mov     [rdi], eax

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
                lea     rdi, [rip + vp_base]
                mov     ebx, IMM32(vp_size)     // 0x1000 or 0x2000

                push    rax                     // provide 8 bytes stack
                mov     r9, rsp
// FIXME        push    4; pop     r8
                mov     r8d, 4                  // PAGE_READWRITE
                mov     rdx, rbx                // size
                mov     rcx, rdi                // address

                sub     rsp, 0x20
                call    [rip + VirtualProtectAddr]                     // VirtualProtect

                lea     rax, [rdi + dir_table]
                mov     [rax + 8*2], IMM32(res_vaddr)
                mov     [rax + 8*2 + 4], IMM32(res_size)
                mov     [rax + 8*3], IMM32(exc_vaddr)
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
                push rcx // 16 aligned when ret from xor decoder, mimic being called
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
        ret     0
// GetKernel32BaseAddr ENDP
// section         GET_KERNEL32_PROC

LoadLibraryA:
        .asciz "LoadLibraryA"
GetProcAddress:
        .asciz "GetProcAddress"
ExitProcess:
        .asciz "ExitProcess"
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
.global END
END:

section UPX_STUB
        push rsi
        push rbp
        lea rbp, [rsp-0x38]
        sub rsp, 0x58

        lea rsi, [rip+coverup_call]
        mov [rbp + 0x10], rbp # var0
        mov rcx, [rsp + 0x30] # var0
        mov [rbp + 8], rcx # copy to var1
        dec rcx # cl: 0xXf
        shl rcx, 2 # 0x3c/60
        shl qword ptr [rbp + 8], cl # var1: 0
        jne never_jmp
                # add offset to LOADER_DECODER
                # use [rbp] just for mimicing
                push rsi
                mov rsi, [rbp - 0x28] # copy to rsi
                mov rcx, [rbp + 8] # var1: 0
                mov rdx, rcx
                dec dx # -1 0xffff
                mov [rbp + 0x10], rdx # var2: 0
                lea rax, [rcx + 1<<15]
                        .reloc . - 4, R_X86_64_16, (1<<15) + loader_decoder_offset_from_coverup_low
                add rsi, rdx
                sub rsi, rax
                lea rax, [rcx + 1<<15]
                        .reloc . - 4, R_X86_64_16, (1<<15) + loader_decoder_offset_from_coverup_high
                push rdx
                push rcx
                sub rdx, rax
                inc rcx
                shl rcx, 4 # 16
                shl rdx, cl # << 16
                add rsi, rdx
                mov rbx, rsi
                sub rbx, [rbp - 0x28] # loader_decoder_offset_from_coverup
                mov [rbp - 0x28], rsi  # copy to rsi
                pop rcx
                pop rdx
                pop rsi
never_jmp:
        call rsi
        add rsp, 0x58
        pop rbp
        pop rsi
        ret

section LOADER_DECODER
# deobfuscate the loader
# rbx: loader_decoder_offset_from_coverup (1st ^ 2nd) byte as xor key
# rcx: 0
# rdx: 0xffff
        push    rbp
        push    rsi
        push    rdi
        push    rbx
        lea     rbp, [rsp - 0x20]
        push    rbp
        sub     rsp, 0x28
        lea     rax, [rcx + 1<<15]
                .reloc . - 4, R_X86_64_16, (1<<15) + loader_size_addend1
        lea     r8, [rcx + 1<<15]
                .reloc . - 4, R_X86_64_16, (1<<15) + loader_size_addend2
        add     r8, rax
        push    r8 # size
        lea     rsi, [rip + upx_start_complement]
        sub     dx, si # camouflage the address, 0xffff - complement
        xchg    dx, si
        push    rsi # upx_start
        pop     rdi # balance
        mov     rdx, [rbp - 0x20] # upx_start
        lea     rax, [rcx + 0x40]
        mov     [rbp + rax], rdx # change return address

        mov     r8, rcx
        inc     r8 # r8: 1
        mov     r10, r8
        shl     r10, 5 # 0x20

        or      rbx, rcx # obf
        push    rbx # rbx: key
        mov     rdi, rbx
        or      rbx, rcx # obf
        not     rdi     # rdi: ~key
        push    rdi
mov     r11, rcx # r11: counter
        lea     rsi, [rip + do_xor]
        push    rsi

        do_xor:
        mov     rbp, [rsp + 0x48] # restore rbp
        mov     rax, [rbp - 0x30]
        # mimic sub rsp, 0x28
        push    rax # copy do_xor as return address
        mov     rsi, [rbp + 0x40] # upx_start
        push    rsi # align
        mov     rdx, [rsi + r11]
        push    rdx # align
        # mimic xor (a&~b) | (~a&b)
        # b = c^d
        # ((a&~c) | (~a&c)) ^d
        mov     r9, rdx
        mov     rax, r9
        not     rax
        push    rax # align
        mov     rbx, [rbp - 0x20] # key
        and     rax, rbx
        mul     r8b
        and     r9, [rbp - 0x28] # ~key
        push    r9  # align
        or      r9, rcx # obf
        or      rax, r9 # xor done
        mov     r9, [rsp + 0x98] # upx_start
        add     r9, r11
        xor     al, bh
        xchg    dl, al  # change only the byte
        mov     [r9 + rcx], rdx # write back

        mov     rax, [rbp - 0x18] # size
        lea     r11, [r11 + r8] # add 1 to counter
        cmpxchg r11, rcx # cmp to rax/size, r11=0 when done, otherwise r11==rax
        mov     rax, r11
        sub     rbp, rsp
        add     rbp, r10
        and     rdx, rcx # clear
        cmpxchg rdx, rbp # rdx: rbp+0x40 when done otherwise 0
        add     rsp, rdx
        pop rbx
        pop rdi
        pop rsi
        pop rbp
        ret
/* vim:set ts=8 sw=8 et: */
