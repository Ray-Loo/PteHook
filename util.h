#pragma once
#pragma once
#include <ntddk.h>
#include <wdm.h>
UINT64 paToVa(UINT64 physicalAddress);
UINT64 vaToPa(UINT64 virtualAddress);

bool MdlWriteMemory(PVOID pBaseAddress, PVOID pWriteData, SIZE_T writeDataSize);