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
EXTERN	 HookTestTarget:PROC
EXTERN g_jmp_testtarget:DQ
EXTERN g_geptDummyVmxonPa:DQ     ;v3.53: VMXON探针哑操作数(PA=0, main.c定义)
EXTERN	 GeptCallbackDispatch:PROC   ;v3.50: API detour分发器(GeptApi.c)
EXTERN	 GeptViewSwitch:PROC         ;v3.50: 带VT开关检查的视图切换(GeptApi.c)
.CODE
;==== v3.51 Phase4/6: API detour stub(统一版, VMFUNC核+fallback核共用) ====
;进入链: hooked视图hook页(=CodePage)目标偏移处的14B绝对跳转
;  → 本hook独享trampoline槽(GeptApi.c生成: mov r10,entry; jmp GeptStubEntry)
;  → 此处。r10=API条目(trampoline写入); 栈顶=原调用者返回地址
;  (PHInitJmpCode的push+ret净值0=纯jmp语义); 原函数参数rcx/rdx/r8/r9原封未动
;流程: GeptViewSwitch(0)切clean(VMFUNC核; fallback核自动no-op)
;  → SAVE_ALL → 分发器(设置每核当前hook+调用户回调, 返回值=新函数返回值)
;  → GeptViewSwitch(1)归位hooked → 回调返回值写帧rax槽
;  → RESTORE_ALL → ret回调用者(rax=回调返回值=detour完整控制权)
;v3.51统一化(Phase 6): 原版入口处裸vmfunc(仅VMFUNC核合法, fallback核
;=#UD蓝屏)改调GeptViewSwitch——C侧按bVmfuncOn按核判定, fallback核
;自动no-op=同一stub服务两类核(混合机器正确)
;v3.51顺带修复两处latent bug(裸vmfunc版靠运气通过v3.50b实测):
;  ①retval曾存r10/r11跨call GeptViewSwitch——volatile寄存器跨C调用
;    不保证保存(当前编译器恰好没占用纯属运气); 现改为**立即落帧**
;    (mov [rsp+28h],rax后不再跨call持有)
;  ②API条目曾假定r10跨call存活——同理不可靠; 现从帧的r10槽重取
;    ([rsp+78h]: SAVE_ALL后r10槽=槽写入的entry值, 偏移28h+50h)
;帧布局(push序=HVM_SAVE_ALL_NOSEGREGS, rax最低): rax@0 rcx@8 rdx@10h
;rbx@18h rbp@20h rsi@30h rdi@38h r8@40h r9@48h r10@50h r11@58h...
;sub 28h后帧基=rsp+28h, 故r10槽=rsp+28h+50h=rsp+78h
GeptStubEntry PROC
    HVM_SAVE_ALL_NOSEGREGS    ;先保存全部(含槽写入的r10=API条目)
    sub rsp, 28h              ;入口RSP%16==8(jmp到函数入口语义)+16push
                              ;(128B)不改奇偶→此处%16==8; sub 28h(40B)
                              ;→call点%16==0, x64 ABI正确(v3.43裁决同款)
    xor ecx, ecx              ;arg1=0(clean视图)
    call GeptViewSwitch       ;VMFUNC核: vmfunc切clean; fallback核: no-op
                              ;(rcx/rdx/r8-r11可能被clobber——无妨)
    mov rcx, [rsp+78h]        ;arg1=API条目(从帧r10槽重取, 不依赖volatile存活)
    lea rdx, [rsp+28h]        ;arg2=GUEST_REGS帧基(回调取原始rcx/rdx/r8/r9)
    call GeptCallbackDispatch ;rax=用户回调返回值=hook函数的新返回值
    mov [rsp+28h], rax        ;**retval立即落帧的rax槽**(不跨下个call持有
                              ;volatile; RESTORE的pop rax=新返回值)
    mov ecx, 1                ;arg1=1(hooked视图)
    call GeptViewSwitch       ;VMFUNC核: vmfunc归位; fallback核: no-op
    add rsp, 28h
    HVM_RESTORE_ALL_NOSEGREGS ;rax=回调返回值, 其余全部=原始值(detour语义)
    ret                       ;回原调用者(栈顶=其返回地址, jmp进入未压新帧)
GeptStubEntry ENDP

;==== 自测目标: 指令布局完全自控, 不依赖任何Windows版本 ====
;前5条mov共15字节(>=14字节跳板), 无相对寻址指令, 可被安全跳板化
;v3.42: **页隔离**——v3.41实测蓝屏的结构性缺陷: 目标原本与
;common-asm.asm(CmGuestRsp/CmGuestProbe/**CmVmCall**/CmTripleFaultPark)和
;AsmHookTestTarget同页(hook.asm与common-asm被链接器排到同一4K页, 实测
;目标=...10D6/跳板=...10E6/探针=...103D/CmVmCall=...1075)——EptSetHook清掉
;该页execute后, DPC自己的vmcall(2)返回路径(ret)就在被hook页上=立即
;violation, 全部VT机器码卷入双视图互切(exec视图write=0=活锁雷区), 且
;自测≠真实场景(STAGE 2 hook的是nt页, 不含我们的代码)。隔离后: 被
;hook页只有16字节GeptTestTarget, 零自指干扰
;v3.42b实现修正: 段内`align 1000h`被ml64拒绝("invalid combination with
;segment alignment:4096"——.code段默认ALIGN(16), 段内align不得超段属性)。
;改用SEGMENT伪指令自定义ALIGN(4096)段: 链接器给GEPTTGT独立PE section,
;内存布局按SectionAlignment(0x1000)整页对齐=目标函数独占一页, 且与
;.code(跳板/AsmHookNtClose)和common-asm.asm物理不同section必然不同页
GEPTTGT SEGMENT ALIGN(4096) 'CODE'
GeptTestTarget PROC
    mov     r11, rcx        ;3字节
    mov     r10, rdx        ;3字节
    mov     r9,  r8         ;3字节
    mov     r8,  r9         ;3字节
    mov     r11, r10        ;3字节
    ret
GeptTestTarget ENDP
GEPTTGT ENDS

;独立section天然把跳板隔到不同页(.code), 无需align(v3.42b)
;(v3.51: GeptStubEntry已移至文件头部统一版; 旧版裸vmfunc stub与
; AsmHookNtClose硬编码重放随Phase 6动态化一并退役删除)

;==== 自测跳板: 重放被跳板覆盖的5条mov, 然后跳回 原函数+15 ====
;v3.43**根因修复**: call HookTestTarget前的sub rsp,20h→28h。
;v3.41/v3.42b两连蓝屏0x1E@(0xC0000005, nt+0x405B4F, 0, -1)的完整机理:
;  ①本函数入口RSP%16==8(跳板push imm32+ret净值0, 等效一次正常call)
;  ②16个push(128B)+sub 20h(32B)都不改RSP%16奇偶→call时RSP%16==8
;    =违反ABI(call前须≡0), HookTestTarget整棵调用树错8字节运行
;  ③HookTestTarget→FlLog等待T1落盘→线程阻塞→调度器在错位栈上
;    调用nt上下文切换shell(sub rsp,138h; movaps [rsp+30h],xmm6...)
;  ④movaps要求16字节对齐, 错8字节→#GP(0); 内核把#GP构造成AV记录
;    (info[0]=0读, info[1]=-1哨兵)→0x1E@(C0000005, nt+0x405B4F, 0, -1)
;  铁证: ntoskrnl反汇编RVA 0x405B4F=movaps xmm6→[rsp+30h], 其worker
;  0x405E90含fxsave/xsave+mov [rdi+58h],rsp+mov rsp,[rsi+58h](栈切换)
;  =KiSwapContext; 两次蓝屏同RVA(确定性调度路径), 页隔离前后同签名
;  (与hook页内容无关), Stage0无此路径从不崩——全部吻合
;28h=32B影子空间(ABI)+8B对齐补偿(与CmGuestRsp的sub 28h同理)
AsmHookTestTarget proc
    HVM_SAVE_ALL_NOSEGREGS
    sub rsp,28h
    call HookTestTarget
    add rsp,28h
    HVM_RESTORE_ALL_NOSEGREGS
    ;重放被跳板覆盖的原始指令(与GeptTestTarget前15字节完全一致)
    mov     r11, rcx
    mov     r10, rdx
    mov     r9,  r8
    mov     r8,  r9
    mov     r11, r10
    jmp qword ptr[g_jmp_testtarget]
AsmHookTestTarget endp

;==== v3.53 v1.0.1: 病毒模拟探针(DriverEntry自测专用, 非hook目标, ====
;==== 与AsmHookTestTarget同页无害——本页永不被EPT hook)            ====
;机器码纪律(v3.47c铁律): VMX指令一律SDM出处手编, 绝不用论坛/记忆值
;  VMXOFF = 0F 01 C4 (SDM VMXOFF页"0F 01 C4 VMXOFF"; v3.47c硬件实证
;            exit rsn26铁证双确认)
;  VMXON  = F3 0F C7 /6 (SDM VMXON页"F3 0F C7 /6 VMXON m64";
;            ModRM=30h→[rax]形, lea免手算disp32)

;VMXOFF探针: guest内执行→VM-exit rsn26→宿主case26注入#UD→内核SEH
;捕获(异常码应=0xC000001D STATUS_ILLEGAL_INSTRUCTION)。**v3.47c确切
;死法的正规判据重放**: 当年这条机器码蓝屏过整机(无case落'U'逃生),
;现在它活着穿过新case=安全修复的毕业判据。仅可在in-guest核调用
;(裸机上=真VMXOFF, 自测流程保证此刻全核in-guest)
GeptVirusVmxDetectOff PROC
    db 0Fh, 01h, 0C4h             ;vmxoff
    ret                            ;到达=宿主未注入#UD(自测判FAIL)
GeptVirusVmxDetectOff ENDP

;VMXON探针: guest内执行→VM-exit rsn27→宿主case27伪造VMfailInvalid
;(CF=1)→setc捕获CF→返回1=VT-x原生互斥仲裁在场的活体证据(同框架
;junior实例的__vmx_on走的就是这条路→VMfail→干净退出)。哑操作数
;PA=0: 宿主伪造VMfail不读操作数(SDM: non-root下VMexit替代指令执行);
;裸机上PA=0非4KB对齐同样VMfailInvalid——探针在两种环境都无副作用
GeptVirusVmxOn PROC
    lea rax, [g_geptDummyVmxonPa] ;操作数地址(哑QWORD)
    db 0F3h, 0Fh, 0C7h, 30h       ;vmxon qword ptr [rax]
    setc al                       ;CF=1=伪造的VMfailInvalid
    movzx rax, al
    ret
GeptVirusVmxOn ENDP
END
