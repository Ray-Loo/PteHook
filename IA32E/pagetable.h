#pragma once
#include <ntifs.h>
#include <ntddk.h>

#include "..\util.h"
#include "..\logger.h"
#include "x64Common.h"
//页表结构体地址
typedef struct _PAGE_TABLE {
    UINT64 LineAddress;
    PML4E* pml4eAddress;
    PDPTE* pdpteAddress;
    PDE* pdeAddress;
    PTE* pteAddress;
}PAGE_TABLE, * PPAGE_TABLE;

namespace page_table {
	PTE* GetPteBase4KB();
    UINT64 getPteBase_by_va(UINT64 virtualAddress);
    void GetPageTable(PAGE_TABLE* pageTable);
}