EXTERN	VmxSetupVmcs:PROC
.CODE
CmGuestRsp PROC
push rax
push rcx
push rdx
push rsi
push rdi
push rbp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
sub rsp,28h
mov rcx,rsp
call VmxSetupVmcs
CmGuestRsp ENDP

CmGeustRip PROC
 add rsp,28h
 pop r15
 pop r14
 pop r13
 pop r12
 pop r11
 pop r10
 pop r9
 pop r8
 pop rbp
 pop rdi
 pop rsi
 pop rdx
 pop rcx
 pop rax
 ret 
CmGeustRip ENDP

CmVmCall PROC
mov rax,rcx
vmcall
ret
CmVmCall ENDP
END
