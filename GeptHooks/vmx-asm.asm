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

;v3.39: C上下文vmx_off跳回guest的专用出口(带非易失GPR恢复)。
;rcx=GuestRegs帧地址(VMM栈上, 布局=HVM_SAVE_ALL_NOSEGREGS的push序),
;rdx=目标RSP, r8=目标RIP。
;为什么必须恢复: x64 ABI下vmcall=调用边界, 调用者(CmVmCall的ret之后
;的VmxStopCpu等)只保证非易失GPR(rbx/rbp/rsi/rdi/r12-r15)跨调用有效
;——而exit handler的C代码(编译器自由使用它们)早已覆盖; 旧VmxJumGuest
;只切RSP+JMP, 跳回后调用者拿handler残留的垃圾寄存器继续跑。
;v3.38 KEEP模式首次成功卸载即实测翻车: "cpu3509829504"垃圾参数打印
;+卸载循环垃圾索引访问g_vcpu→蓝屏0x7E@(0xC0000005, driver+0x558F1)。
;v3.16 EXIT模式从未暴露: 探针vmcall落点=jmp CmGeustRip, pop链从
;guest栈恢复了全部寄存器。
;帧偏移(push序rax,rcx,rdx,rbx,rbp,rbp,rsi,rdi,r8..r15, 与C结构
;GUEST_REGS字段偏移一致): rbx+18h rbp+28h rsi+30h rdi+38h
;r12+60h r13+68h r14+70h r15+78h。易失寄存器(rax/rcx/rdx/r8-r11)
;不恢复: 调用边界后本就无保持义务(合法)
VmxJumGuestRegs PROC
    mov rbx, [rcx + 18h]
    mov rbp, [rcx + 28h]
    mov rsi, [rcx + 30h]
    mov rdi, [rcx + 38h]
    mov r12, [rcx + 60h]
    mov r13, [rcx + 68h]
    mov r14, [rcx + 70h]
    mov r15, [rcx + 78h]
    mov rsp, rdx
    jmp r8
    ret
VmxJumGuestRegs ENDP

;v3.39: 恢复GDTR/IDTR——VM-exit无条件把两个limit压成0xFFFF(SDM 27.5,
;host-state区只有base无limit字段), vmx_off回真机后残留。rcx=10字节描述符
;(WORD limit@+0, QWORD base@+2, 与reg.asm GetGdtBase的sgdt读侧同布局)
VmxLoadGdtr PROC
    lgdt fword ptr [rcx]
    ret
VmxLoadGdtr ENDP
VmxLoadIdtr PROC
    lidt fword ptr [rcx]
    ret
VmxLoadIdtr ENDP
VmxInvd PROC
invd
ret
VmxInvd ENDP

VmxInvept PROC
    invept rcx, OWORD PTR [rdx]
    ret
VmxInvept ENDP
END
