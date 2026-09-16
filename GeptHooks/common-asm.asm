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
sub rsp,28h        ;28h(非20h): x64 ABI要求call指令执行前RSP%16==0
                   ;CmGuestRsp入口RSP%16==8(call压入返回地址), 16个push(128B)不变,
                   ;sub 28h(40B, 40%16==8)后 RSP%16==0 -> VmxSetupVmcs入口%16==8 正确
mov rcx,rsp
call VmxSetupVmcs
CmGuestRsp ENDP

CmGeustRip PROC
 add rsp,28h        ;与CmGuestRsp的sub 28h配对(vmlaunch成功/失败两条路径都经此恢复)
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
