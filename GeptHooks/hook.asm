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
END
