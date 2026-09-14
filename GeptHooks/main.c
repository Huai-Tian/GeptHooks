#include<ntifs.h>
#include"common.h"
#include"winApiDef.h"
#include"PageHook.h"

ULONG64 g_jmp_ntclose = 0;
NTSTATUS AsmHookNtClose(HANDLE hanle);
NTSTATUS HookNtClose()
{

	DbgPrint("ntClose±»HOOKÁË\n");
	return 0;
}
void DriverUload(PDRIVER_OBJECT pDriverObjct)
{
	KeGenericCallDpc(CommVtShutDown, NULL);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObjct,PUNICODE_STRING pRegPath)
{
	
	KeGenericCallDpc(CommVtStart,NULL);
	pDriverObjct->DriverUnload = DriverUload;
	g_jmp_ntclose = (ULONG64)NtClose + 19;
	PHHook(NtClose, AsmHookNtClose);
	return STATUS_SUCCESS;
}