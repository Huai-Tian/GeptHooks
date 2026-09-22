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
EXTERN	 VmxTscCompensate:PROC    ;TSC补偿(exit驻留时长扣除)
.CODE
VmxVmexitHandler PROC
	HVM_SAVE_ALL_NOSEGREGS
	;TSC补偿入口时间戳: 在SAVE_ALL后(guest值已落栈, 易失寄存器可自由
	;使用)。root模式读裸TSC(offset只作用于non-root)
	rdtsc
	shl	rdx, 20h        ;edx:eax→rax全64位(标准序列: shl rdx,32; or)
	or	rax, rdx
	mov	r10, rax         ;r10暂存entryTsc
	mov 	rcx, rsp
	sub	rsp, 0100h    ;VM-exit入口RSP=HOST_RSP(页对齐%16==0, 无返回地址),
	mov	[rsp+0F8h], r10 ;sub 100h(%16==0)后call点对齐正确; entryTsc存
	                 ;[+0F8h](callee只碰[+0..28h]影子空间, [+28h,+100h)不触碰)
	call	VmxExitHandler
	;正常路径: 即将vmresume回guest; 逃生/卸载路径从C内VmxJumGuestRegs
	;跳走, 不返回此处(补偿只在本路径执行)
	mov	rcx, [rsp+0F8h] ;arg1=entryTsc
	rdtsc             ;紧贴vmresume, 测量窗口最大化
	shl	rdx, 20h
	or	rax, rdx
	mov	rdx, rax         ;arg2=exitTsc(此点RSP%16==0, 对齐合法)
	call	VmxTscCompensate ;C: TSC_OFFSET -= 本次exit的root驻留时长
	add	rsp, 0100h
	HVM_RESTORE_ALL_NOSEGREGS
	vmresume ;non-root guest
	jc	VmxResumeFailed   ;CF=1: VMfailValid
	jz	VmxResumeFailed   ;ZF=1: VMfailInvalid
	ret
VmxResumeFailed:
	;vmresume失败: 栈上无有效返回地址不能ret, 交C侧记录后停本核
	sub	rsp, 20h          ;20h: call时保持RSP 16字节对齐(x64 ABI)+影子空间
	call	VmxResumeFailedEntry   ;noreturn
VmxVmexitHandler ENDP


VmxJumGuest PROC
    mov rsp,rcx
    jmp rdx
    ret
VmxJumGuest ENDP

;C上下文vmx_off跳回guest的专用出口(带非易失GPR恢复)。
;rcx=GuestRegs帧地址(VMM栈上, 布局=HVM_SAVE_ALL_NOSEGREGS的push序),
;rdx=目标RSP, r8=目标RIP。
;必须恢复非易失GPR: vmcall是调用边界, 调用者只保证rbx/rbp/rsi/rdi/
;r12-r15跨调用有效, 而exit handler的C代码可能已覆盖它们。
;帧偏移(与C结构GUEST_REGS一致): rbx+18h rbp+28h rsi+30h rdi+38h
;r12+60h r13+68h r14+70h r15+78h。易失寄存器无保持义务, 不恢复
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

;恢复GDTR/IDTR——VM-exit无条件把两个limit压成0xFFFF(SDM 27.5,
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

;返回VMfail标志: invept后RFLAGS.ZF=1表示VMfail(未失效任何TLB项),
;sete al→TRUE=失败。CPU仅支持single-context失效(EPT_VPID_CAP bit26
;==0)时all-context类型会VMfail, EPT TLB实际未失效——调用方必须
;检查返回值并兜底, 否则hook延迟生效
VmxInvept PROC
    invept rcx, OWORD PTR [rdx]
    sete al
    ret
VmxInvept ENDP
END
