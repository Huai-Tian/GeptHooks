#pragma once
#include<ntddk.h>
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[VT][%s]: " format "\n", __FUNCTION__, ##__VA_ARGS__)