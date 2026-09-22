/*
 * Copyright holder: Invisible Things Lab
 */
#pragma once
#include <ntddk.h>
USHORT RegGetCs();
USHORT RegGetDs();
USHORT RegGetEs();
USHORT RegGetSs();
USHORT RegGetFs();
USHORT RegGetGs();
ULONG64 RegGetRflags();
ULONG64 RegGetRsp();

ULONG64 GetIdtBase();
USHORT  GetIdtLimit();
ULONG64 GetGdtBase();
USHORT  GetGdtLimit();

USHORT GetTrSelector();
USHORT GetLdtr();

ULONG64 RegGetDr0();
ULONG64 RegGetDr1();
ULONG64 RegGetDr2();
ULONG64 RegGetDr3();
//
ULONG64 RegSetDr0();
ULONG64 RegSetDr1();
ULONG64 RegSetDr2();
ULONG64 RegSetDr3();