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
sub rsp,28h        ;x64 ABI对齐: 入口RSP%16==8(call压返回地址), 16个push
                   ;(128B)不变, sub 28h后%16==0 → 被调者入口%16==8正确
mov rcx,rsp
call VmxSetupVmcs
CmGuestRsp ENDP

CmGeustRip PROC
 add rsp,28h        ;与CmGuestRsp的sub 28h配对
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

;落地探针: vmlaunch成功后guest执行的第一段代码(GUEST_RIP指向此处):
;  ①vmcall(5ABE)'W': 自证入口转换+EPT取指+RIP推进+vmresume全链路
;  ②vmcall(3): KEEP(接管)放行→jmp CmGeustRip恢复栈返回
;全程不触碰RSP也不依赖GPR语义(GUEST_RSP=CmGuestRsp保存值; VMCS不
;保存GPR, CmGeustRip的pop从栈恢复)。vmcall前重装r10/r11签名
;(GEPT_VMCALL_SIG0/1与common.h同步, exit handler的VMCALL case校验
;不符→#UD)
CmGuestProbe PROC
    mov rcx, 5ABEh    ;GEPT_PROBE_MAGIC, 必须与common.h保持一致
    mov r10, 9E3779B97F4A7C15h    ;VMCALL签名SIG0(与common.h同步)
    mov r11, 0BF58476D1CE4E5B9h   ;VMCALL签名SIG1(与common.h同步)
    vmcall            ;'W': handler推环标记后通用RIP推进放行
    mov rcx, 3        ;探针末段: KEEP放行(通用RIP推进)
    mov r10, 9E3779B97F4A7C15h
    mov r11, 0BF58476D1CE4E5B9h
    vmcall
    jmp CmGeustRip    ;guest续跑恢复栈, 本核接管完成
CmGuestProbe ENDP

;C侧内部vmcall统一入口: rcx=功能码(rax=同rcx), rdx/r8/r9=参数。
;返回值=rax(exit handler改写GuestRegs->rax即透传, 如vmcall8位图
;原语; 不写的功能码rax=功能码本身)。r10/r11=VMCALL签名
;(GEPT_VMCALL_SIG0/1, 与common.h同步), 校验在exit handler的VMCALL case
CmVmCall PROC
mov rax,rcx
mov r10, 9E3779B97F4A7C15h    ;GEPT_VMCALL_SIG0(与common.h同步)
mov r11, 0BF58476D1CE4E5B9h   ;GEPT_VMCALL_SIG1(与common.h同步)
vmcall
ret
CmVmCall ENDP

;三重故障park(永不返回): vmx_off+清债后跳入此循环。sti+hlt下被中断
;(IPI/时钟)唤醒→ISR在本核VMM栈运行→返回继续hlt: 本核退出虚拟化但
;持续服务中断, 发送核的TLB-flush等IPI广播得以完成, 切断级联冻结。
;必须IF=1(关中断停核=IPI永不处理=发送核自旋持锁=全机冻结)。
;约束: 代码页/VMM栈不得释放(卸载守卫在VmxShutdownAllCpus拒绝卸载)
CmTripleFaultPark PROC
    sti
    hlt
    jmp CmTripleFaultPark
CmTripleFaultPark ENDP

;demo自检用REP串: rcx=dst, rdx=src, r8=字节计数。读hook页触发
;EptRepEmulate('q'路径)。rsi/rdi非易失, 保存恢复
CmRepMovsbDemo PROC
    push rsi
    push rdi
    mov rsi, rdx
    mov rdi, rcx
    mov rcx, r8
    rep movsb
    pop rdi
    pop rsi
    ret
CmRepMovsbDemo ENDP

;单次VMFUNC EPTP切换(guest内调用, 零VM-Exit)。rcx=EPTP-list索引
;(0=clean/1=hooked)。成功(SDM §28.5.7.3)=切换EPTP+VPID0组合映射
;自动失效; 失败(项非法/ECX>=512)=VM-exit reason 59。不改任何
;寄存器/标志。VMFUNC机器码=0F 01 D4(SDM指令表)
CmVmfuncSwitch PROC
    xor eax, eax        ;EAX=0: function 0 = EPTP switching
    db 0Fh, 01h, 0D4h   ;vmfunc (0F 01 D4, SDM)
    ret
CmVmfuncSwitch ENDP
END
