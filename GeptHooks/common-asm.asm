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

;落地探针: vmlaunch成功后guest执行的第一段代码(GUEST_RIP指向此处):
;  ①vmcall(rcx=5ABE)'W'   : 自证"入口转换+EPT取指+exit+RIP推进+vmresume"
;  ②512次vmcall(rcx=4)循环(≈6ms)——期间到达的中断在non-root直接经
;    guest IDT交付ISR(硬件原生路径, VMM零参与), 不积压不丢失;
;    若日志出现rsn=1事件=中断直投配置异常(直投下理论不可达)
;  ③vmcall(rcx=6)'Y'      : 循环完成标记(handler推'Y', rbx=0)
;  ④vmcall(rcx=3)         : KEEP模式(接管)直接放行→jmp CmGeustRip恢复栈
;                           →ret回VMXInitCpuStart(non-root)→'Q'→FlLog;
;                           EXIT模式(自测)=vmx_off回真机跳到下一条(jmp)
;全程不触碰RSP(GUEST_RSP=CmGuestRsp保存值, 供CmGeustRip的add/pop/ret恢复;
;直投的ISR帧在RSP之下瞬态使用, 与探针零冲突), 也不依赖GPR语义
;(VMCS不保存GPR, rbx由本探针自行赋值, CmGeustRip的pop会从栈恢复全部寄存器)
;全部四段vmcall携带VMCALL签名r10/r11(GEPT_VMCALL_SIG0/1, 与common.h
;同步——exit handler的VMCALL case校验不符→#UD)。每段vmcall前重新装载:
;直投中断的ISR会clobber易失寄存器r10/r11(探针循环期间中断常态到达)
CmGuestProbe PROC
    mov rcx, 5ABEh    ;GEPT_PROBE_MAGIC, 必须与common.h保持一致
    mov r10, 9E3779B97F4A7C15h    ;VMCALL签名SIG0(与common.h同步)
    mov r11, 0BF58476D1CE4E5B9h   ;VMCALL签名SIG1(与common.h同步)
    vmcall            ;'W': handler推环标记后通用RIP推进放行
    mov rbx, 512      ;512次vmcall(≈6ms): 观测窗口, 兼容历史日志数据
gept_probe_loop:
    mov rcx, 4        ;'L': handler按rbx采样推环(每1024次1条)
    mov r10, 9E3779B97F4A7C15h    ;签名每轮重装: 直投ISR会clobber r10/r11
    mov r11, 0BF58476D1CE4E5B9h
    vmcall
    dec rbx
    jnz gept_probe_loop
    mov rcx, 6        ;'Y': 循环完成(handler推'Y', 携带rbx=0)
    mov r10, 9E3779B97F4A7C15h
    mov r11, 0BF58476D1CE4E5B9h
    vmcall
    mov rcx, 3        ;按GEPT_PROBE_EXIT(common.h开关)分流
    mov r10, 9E3779B97F4A7C15h
    mov r11, 0BF58476D1CE4E5B9h
    vmcall            ;KEEP=放行; EXIT=vmx_off回真机跳到下一条
    jmp CmGeustRip    ;KEEP: guest续跑恢复栈; EXIT: 真机执行(纯jmp安全)
CmGuestProbe ENDP

;C侧内部vmcall统一入口(P0-2签名门配套):
;rcx=功能码(C ABI第1参, mov rax,rcx保留历史双份), rdx/r8/r9=参数。
;r10/r11=VMCALL签名(GEPT_VMCALL_SIG0/1, 与common.h同步)——全部C侧
;调用方(卸载vmcall(1)/布防vmcall(2)/还原vmcall(7))经此装载, 签名
;校验在exit handler的VMCALL case。r10/r11=易失寄存器, C调用方跨调用
;无保持义务, 零破坏
CmVmCall PROC
mov rax,rcx
mov r10, 9E3779B97F4A7C15h    ;GEPT_VMCALL_SIG0(与common.h同步)
mov r11, 0BF58476D1CE4E5B9h   ;GEPT_VMCALL_SIG1(与common.h同步)
vmcall
ret
CmVmCall ENDP

;三重故障park本体(永不返回)——VmxTripleFaultPark在vmx_off+清债后
;跳入此循环。sti+hlt: hlt在IF=1下被任意中断(IPI/时钟/设备)唤醒, ISR在
;本核VMM栈上运行并返回, 然后继续hlt。效果: 本核退出虚拟化但持续服务
;中断——TLB-flush等IPI广播的发送核等待解除, 级联冻结被切断, 机器存活。
;注意: 绝不能用IF=0的停核(_disable+__halt)=IPI永不处理=发送核自旋
;持锁=全机冻结。
;约束: 代码页/VMM栈绝不能释放(驱动不得卸载——main.c卸载守卫拒绝)。
;不触碰任何GPR/栈(唤醒的ISR帧在RSP之下瞬态使用), 纯3指令循环
CmTripleFaultPark PROC
    sti
    hlt
    jmp CmTripleFaultPark
CmTripleFaultPark ENDP

;单次VMFUNC EPTP切换(guest内调用, 零VM-Exit)。
;rcx=EPTP-list索引(0=clean/1=hooked), C侧ULONG参数零扩展到RCX天然合法。
;语义(SDM §28.5.7.3): 成功=新EPTP写回EPT_POINTER字段+后续翻译走新表
;+VPID0组合映射自动失效; 失败(项非法/ECX>=512)=VM-exit reason 59
;(handler case59推RIP跳过)。vmfunc不改任何寄存器/标志(SDM:
;"does not modify the state of any registers"), 纯切换语义。
;机器码纪律: VMFUNC=0F 01 D4(SDM指令表)——绝不凭记忆/论坛写opcode
CmVmfuncSwitch PROC
    xor eax, eax        ;EAX=0: function 0 = EPTP switching
    db 0Fh, 01h, 0D4h   ;vmfunc (0F 01 D4, SDM)
    ret
CmVmfuncSwitch ENDP
END
