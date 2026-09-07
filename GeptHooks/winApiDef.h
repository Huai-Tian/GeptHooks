#pragma once
#include<ntifs.h>
EXTERN_C VOID KeGenericCallDpc(__in PKDEFERRED_ROUTINE Routine, __in_opt PVOID Context);
EXTERN_C VOID KeSignalCallDpcDone(__in PVOID SystemArgument1);
EXTERN_C LOGICAL KeSignalCallDpcSynchronize(__in PVOID SystemArgument2);