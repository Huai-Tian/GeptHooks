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
EXTERN	 VmxResumeFailedEntry:PROC
.CODE
VmxVmexitHandler PROC
	HVM_SAVE_ALL_NOSEGREGS
	mov 	rcx, rsp
	sub	rsp, 0100h    ;100h(非108h): VM-exit入口RSP=HOST_RSP(页对齐,%16==0,无返回地址),
	call	VmxExitHandler   ;16个push(128B)不变, sub 100h(256B,%16==0)后调用点RSP%16==0正确
	add	rsp, 0100h
	HVM_RESTORE_ALL_NOSEGREGS
	vmresume ;non-root guest
	jc	VmxResumeFailed   ;CF=1: VMfailValid
	jz	VmxResumeFailed   ;ZF=1: VMfailInvalid
	ret
VmxResumeFailed:
	;vmresume失败: 原版直接ret, 栈上无有效返回地址=未定义行为
	;改为进入C侧记录'R'标记后停掉本核(其余核由心跳日志继续观测)
	sub	rsp, 20h          ;20h: call时保持RSP 16字节对齐(x64 ABI)+影子空间
	call	VmxResumeFailedEntry   ;noreturn
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
