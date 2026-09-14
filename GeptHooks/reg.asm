
.CODE
RegGetCs PROC
	mov		rax, cs
	ret
RegGetCs ENDP

RegGetDs PROC
	mov		rax, ds
	ret
RegGetDs ENDP

RegGetEs PROC
	mov		rax, es
	ret
RegGetEs ENDP

RegGetSs PROC
	mov		rax, ss
	ret
RegGetSs ENDP

RegGetFs PROC
	mov		rax, fs
	ret
RegGetFs ENDP

RegGetGs PROC
	mov		rax, gs
	ret
RegGetGs ENDP


RegGetDr0 PROC
	mov		rax, dr0
	ret
RegGetDr0 ENDP

RegGetDr1 PROC
	mov		rax, dr1
	ret
RegGetDr1 ENDP

RegGetDr2 PROC
	mov		rax, dr2
	ret
RegGetDr2 ENDP

RegGetDr3 PROC
	mov		rax, dr3
	ret
RegGetDr3 ENDP

RegSetDr0 PROC
	mov		dr0, rcx
	ret
RegSetDr0 ENDP

RegSetDr1 PROC
	mov		dr1, rcx
	ret
RegSetDr1 ENDP

RegSetDr2 PROC
	mov		dr2, rcx
	ret
RegSetDr2 ENDP

RegSetDr3 PROC
	mov		dr3, rcx
	ret
RegSetDr3 ENDP


RegGetRflags PROC
	pushfq
	pop		rax
	ret
RegGetRflags ENDP

RegGetRsp PROC
	mov		rax, rsp
	add		rax, 8
	ret
RegGetRsp ENDP

GetIdtBase PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, QWORD PTR idtr[2]
	ret
GetIdtBase ENDP

GetIdtLimit PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		ax, WORD PTR idtr[0]
	ret
GetIdtLimit ENDP

GetGdtBase PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		rax, QWORD PTR gdtr[2]
	ret
GetGdtBase ENDP

GetGdtLimit PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
GetGdtLimit ENDP


GetLdtr PROC
	sldt	rax
	ret
GetLdtr ENDP

GetTrSelector PROC
	str	rax
	ret
GetTrSelector ENDP


END
