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
EXTERN	 GeptCallbackDispatch:PROC   ;API detour分发器(GeptApi.c)
.CODE
;==== API detour stub(双EPT核+fallback核共用) ====
;进入链: hooked视图hook页(=CodePage)目标偏移14B跳转 → trampoline槽
;  (mov r10,entry; jmp GeptStubEntry) → 此处。r10=API条目; 栈顶=原
;  调用者返回地址(push+ret净值0=纯jmp); rcx/rdx/r8/r9原封未动
;流程: SAVE_ALL → GeptCallbackDispatch(调用户回调, 返回值=新函数
;  返回值) → RESTORE_ALL → ret回调用者。
;回调恒在当前视图执行(视图是核级状态, stub级切换=线程迁移后旧核
;视图错乱的竞态源——v1.10b移除): 回调调用的其他hook目标正常触发
;  (嵌套detour语义); GeptCallOriginal走重定位跳板(视图无关)。
;retval/API条目必须立即落帧(volatile跨C调用不保证保存)
;帧布局(push序, rax最低): rax@0 rcx@8 rdx@10h rbx@18h rbp@20h
;rsi@30h rdi@38h r8@40h r9@48h r10@50h r11@58h; sub 28h后帧基=
;rsp+28h, r10槽=rsp+78h
;栈参数(x64 ABI, RSP0=帧基+80h): [RSP0]=调用者返回地址,
;[RSP0+8h..+27h]=影子空间, [RSP0+28h]=第5参首址(C侧取regs->rsp+28h)
GeptStubEntry PROC
    HVM_SAVE_ALL_NOSEGREGS    ;保存全部(含r10=API条目)
    lea  rax, [rsp+80h]       ;RSP0=guest入口rsp(SAVE_ALL帧0x80之上)
    mov  [rsp+20h], rax       ;写GUEST_REGS.rsp槽(双push rbp的假槽,
                              ;RESTORE时被pop rbp覆盖; C侧栈参数=regs->rsp+28h)
    sub rsp, 28h              ;入口%16==8+16push(128B)不变, sub 28h后
                              ;call点%16==0(须28h非20h, 否则栈错位#GP)
    mov rcx, [rsp+78h]        ;arg1=API条目(从帧r10槽重取)
    lea rdx, [rsp+28h]        ;arg2=GUEST_REGS帧基(回调取原始rcx/rdx/r8/r9)
    call GeptCallbackDispatch ;rax=用户回调返回值
    mov [rsp+28h], rax        ;retval落帧rax槽(RESTORE的pop rax=新返回值)
    add rsp, 28h
    HVM_RESTORE_ALL_NOSEGREGS ;rax=回调返回值, 其余全部=原始值(detour语义)
    ret                       ;回原调用者(栈顶=其返回地址, jmp进入未压新帧)
GeptStubEntry ENDP

;==== CallOriginal第5+栈参数转发桩(GeptApi.c GeptCallOriginal调用) ====
;rcx=GEPT_ORIG_CALL*(参数块偏移契约): +00h Target(重定位跳板, 视图无关)
;+08h StackArgs源(触发帧第5+实参, 可被回调改写)
;+10h Count(N) +18h Arg1 +20h Arg2 +28h Arg3 +30h Arg4
;职责: 按x64 ABI重建对Target的调用帧——32B影子空间+N个栈参数复制到
;[rsp+20h..]+寄存器参数装载+call点16对齐。
;栈对齐: 入口%16==8, push rbp(帧锚)+rbx/rsi/rdi/rcx(4×8)+sub 120h
;(16倍数)→call点%16==0。固定布局使arg5恒在[rsp+20h], 与N奇偶无关。
;120h=影子20h+栈参区100h(32槽, N≤32只填前N槽)
;PROC FRAME+unwind指令: 被调Target抛异常且上层SEH捕获时, 内核
;unwinder可正确穿越本帧
GeptCallOrigAsm PROC FRAME
    push rbp
    .pushreg rbp
    mov  rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push rcx                    ;参数块指针存档@[rbp-20h](循环后重取)
    .pushreg rcx
    sub  rsp, 120h
    .allocstack 120h
    .endprolog
    mov  rbx, [rcx]             ;Target
    mov  rsi, [rcx+08h]         ;栈参源
    mov  rdi, [rcx+10h]         ;N(0=仅寄存器参数)
    ;正向复制N个栈参→[rsp+20h..](dst连续, 源只读; N=0跳过)
    test rdi, rdi
    jz   @F
    lea  rcx, [rsp+20h]         ;dst=影子空间之上的栈参区首址
    xor  edx, edx               ;i=0
gco_copy:
    mov  rax, [rsi+rdx*8]       ;StackArgs[i]→[rsp+20h+i*8]
    mov  [rcx+rdx*8], rax
    inc  rdx
    cmp  rdx, rdi
    jb   gco_copy
@@:
    ;装载寄存器参数(参数块指针从[rbp-20h]重取)
    mov  rax, [rbp-20h]
    mov  rcx, [rax+18h]         ;Arg1
    mov  rdx, [rax+20h]         ;Arg2
    mov  r8,  [rax+28h]         ;Arg3
    mov  r9,  [rax+30h]         ;Arg4
    call rbx                    ;[rsp..1Fh]=影子, [rsp+20h..]=arg5..; rax透传
    lea  rsp, [rbp-18h]         ;帧回收(跳过rcx存档槽)
    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
GeptCallOrigAsm ENDP
END
