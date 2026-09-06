#include"Defines.h"

EXTERN_C VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	Log("Completed!");
}
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	Log("Loaded!");
	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}