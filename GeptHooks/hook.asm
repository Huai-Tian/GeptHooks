HVM_SAVE_ALL_NOSEGREGS MACRO
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8        
        push rdi
        push rsi
        push rbp
        push rbp
        push rbx
        push rdx
        push rcx
        push rax
ENDM
HVM_RESTORE_ALL_NOSEGREGS MACRO
        pop rax
        pop rcx
        pop rdx
        pop rbx
        pop rbp
        pop rbp
        pop rsi
        pop rdi 
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
ENDM
EXTERN	 HookNtClose:PROC
EXTERN g_jmp_ntclose:DQ
EXTERN	 HookTestTarget:PROC
EXTERN g_jmp_testtarget:DQ
.CODE
AsmHookNtClose proc
    HVM_SAVE_ALL_NOSEGREGS
    sub rsp,20h
    call HookNtClose
    add rsp,20h
    HVM_RESTORE_ALL_NOSEGREGS
    mov     [rsp+8], rbx
    push    rdi
    sub     rsp, 20h
    mov     rax, gs:[188h]
   jmp qword ptr[g_jmp_ntclose]
AsmHookNtClose endp

;==== 自测目标: 指令布局完全自控, 不依赖任何Windows版本 ====
;前5条mov共15字节(>=14字节跳板), 无相对寻址指令, 可被安全跳板化
GeptTestTarget PROC
    mov     r11, rcx        ;3字节
    mov     r10, rdx        ;3字节
    mov     r9,  r8         ;3字节
    mov     r8,  r9         ;3字节
    mov     r11, r10        ;3字节
    ret
GeptTestTarget ENDP

;==== 自测跳板: 重放被覆盖的5条mov, 然后跳回 原函数+15 ====
AsmHookTestTarget proc
    HVM_SAVE_ALL_NOSEGREGS
    sub rsp,20h
    call HookTestTarget
    add rsp,20h
    HVM_RESTORE_ALL_NOSEGREGS
    ;重放被跳板覆盖的原始指令(与GeptTestTarget前15字节完全一致)
    mov     r11, rcx
    mov     r10, rdx
    mov     r9,  r8
    mov     r8,  r9
    mov     r11, r10
    jmp qword ptr[g_jmp_testtarget]
AsmHookTestTarget endp
END
