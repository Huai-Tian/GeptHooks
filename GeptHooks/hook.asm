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
EXTERN	 GeptCallbackDispatch:PROC   ;v3.50: API detour分发器(GeptApi.c)
EXTERN	 GeptViewSwitch:PROC         ;v3.50: 带VT开关检查的视图切换(GeptApi.c)
.CODE
;v1.2: 自测目标与病毒探针(GeptTestTarget/GeptTestTarget6/AsmHookTestTarget/
;GeptVirusVmxDetectOff/GeptVirusVmxOn)整体退役——开发期验证专用, API使用
;者不需要(验证史见NOTES.md); 本文件只保留API运行时必需的两个入口:
;GeptStubEntry(hook触发链)与GeptCallOrigAsm(第5+栈参数转发桩)
;
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
;v1.1栈参数布局(触发时guest栈=帧基+80h起, x64 ABI): [+80h]=调用者
;返回地址 [+88h..+A7h]=影子空间(调用者分配32B) [+A8h]=第5参
;[+B0h]=第6参...——RSP0(=帧基+80h)视角: [RSP0]=返回地址,
;[RSP0+28h]=第5参首址(影子空间之上), C侧统一用regs->rsp+28h
GeptStubEntry PROC
    HVM_SAVE_ALL_NOSEGREGS    ;先保存全部(含槽写入的r10=API条目)
    lea  rax, [rsp+80h]       ;v1.1: RSP0=guest入口rsp(SAVE_ALL帧高
                              ;0x80之上; rax此刻已保存在帧内, clobber安全)
    mov  [rsp+20h], rax       ;帧rsp槽=GUEST_REGS.rsp=RSP0(旧值无用——
                              ;双push rbp的假槽, RESTORE时被首个pop rbp
                              ;读后即被真rbp覆盖; C侧栈参数=regs->rsp+28h)
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

;==== v1.1: CallOriginal第5+栈参数转发桩(GeptApi.c GeptCallOriginal调用) ====
;rcx=GEPT_ORIG_CALL*(C侧GeptCallOriginal栈上参数块, 偏移硬契约):
;  +00h Target(VMFUNC核=原入口/fallback核=重定位跳板)
;  +08h StackArgs源(=触发帧上第5+实参, 回调可已改写)  +10h Count(N)
;  +18h Arg1  +20h Arg2  +28h Arg3  +30h Arg4
;职责: 按x64 ABI重建对Target的完整调用帧——32B影子空间+N个栈参数
;(从源逐个复制到[rsp+20h..])+rcx/rdx/r8/r9装载+call点16对齐。
;栈帧精算(入口rsp%16==8): push rbp→0(rbp=帧锚, rbp%16==0); push
;rbx/rsi/rdi/rcx(4×8=20h)→rsp%16==0; sub 120h(288B, 16倍数)→call点
;%16==0 OK。固定布局的**本质优点**: arg5恒在[rsp+20h](影子之上),
;与N奇偶无关——动态sub方案的N奇偶对齐补偿问题构造性不存在
;120h=影子20h+栈参区100h(32槽×8B, N≤32只填前N槽, 余槽callee不读)
;PROC FRAME+unwind指令(.pushreg/.allocstack/.setframe): 被调Target
;抛#GP/#PF且上层SEH捕获时, 内核unwinder可正确穿越本帧走栈
;(缺unwind信息=异常派发期二次崩溃; v3.53起宿主会向guest注入
;#GP/#UD, 异常穿越本帧属真实可达路径, 纯防御纵深)
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
    push rcx                    ;参数块指针存档@[rbp-20h](rcx=caller
    .pushreg rcx                ;-saved无需还原, 存档只为循环后重取)
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
    mov  rax, [rsi+rdx*8]       ;rax=StackArgs[i](参数块已不再需要,
    mov  [rcx+rdx*8], rax       ;     volatile可任意征用)
    inc  rdx
    cmp  rdx, rdi
    jb   gco_copy
@@:
    ;装载寄存器参数(参数块指针从[rbp-20h]重取——rcx已被复制循环征用)
    mov  rax, [rbp-20h]
    mov  rcx, [rax+18h]         ;Arg1
    mov  rdx, [rax+20h]         ;Arg2
    mov  r8,  [rax+28h]         ;Arg3
    mov  r9,  [rax+30h]         ;Arg4
    call rbx                    ;rsp%16==0, [rsp..1Fh]=影子, [rsp+20h..]
                                ;=arg5..(全按ABI); rax=Target返回值透传
    lea  rsp, [rbp-18h]         ;固定帧回收(跳过rcx存档槽=volatile不还原)
    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
GeptCallOrigAsm ENDP
END
