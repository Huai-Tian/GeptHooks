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
EXTERN	 VmxExitHandler:PROC
.CODE
VmxVmexitHandler PROC
	HVM_SAVE_ALL_NOSEGREGS
	mov 	rcx, rsp		 
	sub	rsp, 0100h
	call	VmxExitHandler
	add	rsp, 0100h
	HVM_RESTORE_ALL_NOSEGREGS	
	vmresume ;non-root guest
	ret
VmxVmexitHandler ENDP


VmxJumGuest PROC
    mov rsp,rcx
    jmp rdx
    ret
VmxJumGuest ENDP
VmxInvd PROC
invd
ret
VmxInvd ENDP

VmxInvept PROC
    invept rcx, OWORD PTR [rdx]
    ret
VmxInvept ENDP
END
