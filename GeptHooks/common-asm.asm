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

;v3.13落地探针: vmlaunch成功后guest执行的第一段代码(GUEST_RIP指向此处)。
;v3.20改为四段(把接管冻结的死亡窗口切成可观测片段); v3.36中断直投版:
;  ①vmcall(rcx=5ABE)'W'   : 自证"入口转换+EPT取指+exit+RIP推进+vmresume"
;  ②512次vmcall(rcx=4)循环(≈6ms)——v3.36直投(pin=0): 期间到达的中断在
;    non-root直接经guest IDT交付ISR(硬件原生路径, VMM零参与), 不积压
;    不丢失; 若日志出现rsn=1事件=配置异常(直投下理论不可达)
;  ③vmcall(rcx=6)'Y'      : 循环完成标记(handler推'Y', rbx=0)
;  ④vmcall(rcx=3)         : KEEP模式(接管)直接放行→jmp CmGeustRip恢复栈
;                           →ret回VMXInitCpuStart(non-root)→'Q'→FlLog;
;                           EXIT模式(自测)=vmx_off回真机跳到下一条(jmp)
;全程不触碰RSP(GUEST_RSP=CmGuestRsp保存值, 供CmGeustRip的add/pop/ret恢复;
;直投的ISR帧在RSP之下瞬态使用, 与探针零冲突), 也不依赖GPR语义
;(VMCS不保存GPR, rbx由本探针自行赋值, CmGeustRip的pop会从栈恢复全部寄存器)
CmGuestProbe PROC
    mov rcx, 5ABEh    ;GEPT_PROBE_MAGIC, 必须与common.h保持一致
    vmcall            ;'W': handler推环标记后通用RIP推进放行
    mov rbx, 512      ;v3.36: 保持512次(≈6ms)——直投模式下循环期间中断
                      ;原样直投ISR(LAPIC IRR零积压), 循环长度已无安全含义,
                      ;留此值纯粹为与v3.29-3.35的观测数据可比
gept_probe_loop:
    mov rcx, 4        ;'L': handler按rbx采样推环(每1024次1条)
    vmcall
    dec rbx
    jnz gept_probe_loop
    mov rcx, 6        ;'Y': 循环完成(handler推'Y', 携带rbx=0)
    vmcall
    mov rcx, 3        ;按GEPT_PROBE_EXIT(common.h开关)分流
    vmcall            ;KEEP=放行; EXIT=vmx_off回真机跳到下一条
    jmp CmGeustRip    ;KEEP: guest续跑恢复栈; EXIT: 真机执行(纯jmp安全)
CmGuestProbe ENDP

CmVmCall PROC
mov rax,rcx
vmcall
ret
CmVmCall ENDP

;v3.35: 三重故障park本体(永不返回)——VmxTripleFaultPark在vmx_off+清债后
;跳入此循环。sti+hlt: hlt在IF=1下被任意中断(IPI/时钟/设备)唤醒, ISR在本核
;VMM栈上运行并返回, 然后继续hlt。**效果: 本核退出虚拟化但持续服务中断**
;——TLB-flush等IPI广播的发送核等待解除, 级联冻结被从根上切断, 机器存活,
;T1把'T'+环尾事件全部落盘(对比v3.10的_disable+__halt: IF=0停核=IPI永不
;处理=发送核自旋持锁=全机冻结=v3.30-34五连"零事件+看门狗死"的统一解释)。
;约束: 代码页/VMM栈绝不能释放(驱动不得卸载——main.c卸载守卫拒绝)。
;不触碰任何GPR/栈(唤醒的ISR帧在RSP之下瞬态使用), 纯3指令循环
CmTripleFaultPark PROC
    sti
    hlt
    jmp CmTripleFaultPark
CmTripleFaultPark ENDP
END
