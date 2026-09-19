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
EXTERN	 HookNtClose:PROC
EXTERN g_jmp_ntclose:DQ
EXTERN	 HookTestTarget:PROC
EXTERN g_jmp_testtarget:DQ
.CODE
AsmHookNtClose proc
    HVM_SAVE_ALL_NOSEGREGS
    ;v3.43: 20h→28h——x64 ABI要求call指令执行前RSP%16==0。入口RSP%16==8
    ;(call压入返回地址后), 16个push(128B)不改奇偶, 20h(32B)也不改→call时
    ;RSP%16==8=错8字节! HookNtClose及整棵子树全部错位运行, 直到某处
    ;编译器按ABI假设发出的movaps(16字节对齐SSE)打到未对齐栈槽→#GP(0)
    ;(v3.41/v3.42b蓝屏0x1E@(C0000005,nt+0x405B4F,0,-1)即此: nt的上下文
    ;切换shell在错位栈上保存xmm6触发)。28h=32B影子空间+8B对齐补偿
    sub rsp,28h
    call HookNtClose
    add rsp,28h
    HVM_RESTORE_ALL_NOSEGREGS
    ;以下重放NtClose原始prologue(与原指令逐字节一致, RSP语义必须相同)
    mov     [rsp+8], rbx
    push    rdi
    sub     rsp, 20h
    mov     rax, gs:[188h]
   jmp qword ptr[g_jmp_ntclose]
AsmHookNtClose endp

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
.code
;==== 自测跳板: 重放被覆盖的5条mov, 然后跳回 原函数+15 ====
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
END
