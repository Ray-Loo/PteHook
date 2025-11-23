#include <ntifs.h>
#include <intrin.h>

#define DEBUG_PRINT(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[PTE_HOOK] " fmt, __VA_ARGS__)
#define PAGE_SIZE 0x1000
#define MAX_HOOK_COUNT 32
#define CR0_WP (1 << 16)
typedef unsigned long uint32_t;
typedef unsigned char uint8_t;

typedef unsigned long long QWORD;
typedef unsigned char BYTE;

typedef union _PTE {
    struct {
        QWORD Present : 1;
        QWORD ReadWrite : 1;
        QWORD UserSupervisor : 1;
        QWORD PageLevelWriteThrough : 1;
        QWORD PageLevelCacheDisable : 1;
        QWORD Accessed : 1;
        QWORD Dirty : 1;
        QWORD PageAttributeTable : 1;
        QWORD Global : 1;
        QWORD CopyOnWrite : 1;
        QWORD Prototype : 1;
        QWORD reserved1 : 1;
        QWORD PageFrameNumber : 36;
        QWORD reserved2 : 4;
        QWORD SoftwareWsIndex : 11;
        QWORD NoExecute : 1;
    };
    QWORD AsUlonglong;
} PTE, * PPTE;

typedef union _PDE {
    struct {
        QWORD Present : 1;
        QWORD ReadWrite : 1;
        QWORD UserSupervisor : 1;
        QWORD PageLevelWriteThrough : 1;
        QWORD PageLevelCacheDisable : 1;
        QWORD Accessed : 1;
        QWORD Dirty : 1;
        QWORD LargePage : 1;
        QWORD Global : 1;
        QWORD CopyOnWrite : 1;
        QWORD Prototype : 1;
        QWORD reserved1 : 1;
        QWORD PageFrameNumber : 36;
        QWORD reserved2 : 4;
        QWORD SoftwareWsIndex : 11;
        QWORD NoExecute : 1;
    };
    QWORD AsUlonglong;
} PDE, * PPDE;

typedef union _PDPTE {
    struct {
        QWORD Present : 1;
        QWORD ReadWrite : 1;
        QWORD UserSupervisor : 1;
        QWORD PageLevelWriteThrough : 1;
        QWORD PageLevelCacheDisable : 1;
        QWORD Accessed : 1;
        QWORD Dirty : 1;
        QWORD PageSize : 1;
        QWORD reserved1 : 4;
        QWORD PageFrameNumber : 36;
        QWORD reserved2 : 4;
        QWORD SoftwareWsIndex : 11;
        QWORD NoExecute : 1;
    };
    QWORD AsUlonglong;
} PDPTE, * PPDPTE;

typedef union _PML4E {
    struct {
        QWORD Present : 1;
        QWORD ReadWrite : 1;
        QWORD UserSupervisor : 1;
        QWORD PageLevelWriteThrough : 1;
        QWORD PageLevelCacheDisable : 1;
        QWORD Accessed : 1;
        QWORD Dirty : 1;
        QWORD reserved1 : 1;
        QWORD reserved2 : 4;
        QWORD PageFrameNumber : 36;
        QWORD reserved3 : 4;
        QWORD SoftwareWsIndex : 11;
        QWORD NoExecute : 1;
    };
    QWORD AsUlonglong;
} PML4E, * PPML4E;

typedef union _CR3 {
    struct {
        QWORD flags : 3;
        QWORD reserved_1 : 5;
        QWORD pwt : 1;
        QWORD pcd : 1;
        QWORD reserved_2 : 4;
        QWORD address_of_page_directory : 36;
        QWORD reserved_3 : 16;
    };
    QWORD AsUlonglong;
} CR3;

typedef struct _PTE_TABLE {
    void* LineAddress;
    PTE* PteAddress;
    PDE* PdeAddress;
    PDPTE* PdpteAddress;
    PML4E* Pml4eAddress;
    BOOLEAN IsLargePage;
    BOOLEAN Is1GBPage;
} PTE_TABLE, * PPTE_TABLE;

typedef struct _HOOK_INFO {
    HANDLE pid;
    void* oriAddr;
    BYTE oriBytes[14];
} HOOK_INFO, * PHOOK_INFO;

static HOOK_INFO m_info[MAX_HOOK_COUNT] = { 0 };
static int m_curHookCount = 0;
static void* m_PTEBase = NULL;
static char* m_trampLine = NULL;
static int m_trampLineUsed = 0;

static QWORD read_cr3() {
    return __readcr3();
}

static void invalidate_page(void* addr) {
    __invlpg(addr);
}

static void* physical_to_virtual(QWORD pa) {
    PHYSICAL_ADDRESS physAddr;
    physAddr.QuadPart = pa;
    return MmGetVirtualForPhysical(physAddr);
}

static QWORD virtual_to_physical(void* va) {
    return MmGetPhysicalAddress(va).QuadPart;
}

static void* get_pte_base() {
    PHYSICAL_ADDRESS cr3_pa;
    cr3_pa.QuadPart = __readcr3() & ~0xFFF;

    void* pml4 = MmGetVirtualForPhysical(cr3_pa);
    if (!pml4) return NULL;

    for (int i = 0; i < 512; i++) {
        PML4E* entry = (PML4E*)((QWORD)pml4 + i * sizeof(PML4E));
        if ((entry->AsUlonglong & 0xFFFFFFFFFF000) == cr3_pa.QuadPart) {
            return (void*)((QWORD)pml4 & 0xFFFFFFFFFFFFF000);
        }
    }
    return NULL;
}

static bool get_pages_table(PTE_TABLE* Table) {
    QWORD va = (QWORD)Table->LineAddress;
    QWORD pml4e_index = (va >> 39) & 0x1FF;
    QWORD pdpte_index = (va >> 30) & 0x1FF;
    QWORD pde_index = (va >> 21) & 0x1FF;
    QWORD pte_index = (va >> 12) & 0x1FF;

    QWORD cr3 = __readcr3();
    QWORD pml4_pa = cr3 & ~0xFFF;//计算物理地址
    PML4E* pml4 = (PML4E*)physical_to_virtual(pml4_pa);//转换为虚拟地址
    if (!pml4) return false;

    Table->Pml4eAddress = &pml4[pml4e_index];
    if (!Table->Pml4eAddress->Present) return false;

    QWORD pdpt_pa = Table->Pml4eAddress->PageFrameNumber << 12;
    PDPTE* pdpt = (PDPTE*)physical_to_virtual(pdpt_pa);
    if (!pdpt) return false;
    Table->PdpteAddress = &pdpt[pdpte_index];
    if (!Table->PdpteAddress->Present) return false;

    if (Table->PdpteAddress->PageSize) {
        Table->Is1GBPage = true;
        return true;
    }

    QWORD pd_pa = Table->PdpteAddress->PageFrameNumber << 12;
    PDE* pd = (PDE*)physical_to_virtual(pd_pa);
    if (!pd) return false;
    Table->PdeAddress = &pd[pde_index];
    if (!Table->PdeAddress->Present) return false;

    if (Table->PdeAddress->LargePage) {
        Table->IsLargePage = true;
        return true;
    }

    QWORD pt_pa = Table->PdeAddress->PageFrameNumber << 12;
    PTE* pt = (PTE*)physical_to_virtual(pt_pa);
    if (!pt) return false;
    Table->PteAddress = &pt[pte_index];

    return Table->PteAddress->Present;
}

static bool split_large_pages(PDE* in_pde, PDE* out_pde) {
    PHYSICAL_ADDRESS LowAddr = { 0 }, HighAddr = { 0 };
    HighAddr.QuadPart = MAXULONG64;

    PTE* Pt = (PTE*)MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, LowAddr, HighAddr, LowAddr, MmNonCached);

    if (!Pt) {
        DEBUG_PRINT("Failed to allocate memory for new PT\n");
        return false;
    }

    QWORD start_pfn = in_pde->PageFrameNumber;
    for (int i = 0; i < 512; i++) {
        Pt[i].AsUlonglong = 0;
        Pt[i].Present = in_pde->Present;
        Pt[i].ReadWrite = in_pde->ReadWrite;
        Pt[i].UserSupervisor = in_pde->UserSupervisor;
        Pt[i].PageLevelWriteThrough = in_pde->PageLevelWriteThrough;
        Pt[i].PageLevelCacheDisable = in_pde->PageLevelCacheDisable;
        Pt[i].Accessed = in_pde->Accessed;
        Pt[i].Dirty = in_pde->Dirty;
        Pt[i].Global = 0;
        Pt[i].PageFrameNumber = start_pfn + i;
    }

    out_pde->AsUlonglong = in_pde->AsUlonglong;
    out_pde->LargePage = 0;
    out_pde->PageFrameNumber = virtual_to_physical(Pt) >> 12;

    DEBUG_PRINT("Split large page: PFN=0x%llx -> new PT at 0x%p\n", start_pfn, Pt);
    return true;
}

static bool isolate_page_table(CR3 cr3_reg, void* replaceAlignAddr, PDE* splitPDE) {
    DEBUG_PRINT("Isolating page table for address: 0x%p\n", replaceAlignAddr);

    // 详细调试信息
    DEBUG_PRINT("CR3 value: 0x%llx\n", cr3_reg.AsUlonglong);
    QWORD pml4_pa = cr3_reg.AsUlonglong & ~0xFFF;//获取了PML4表的物理地址
    DEBUG_PRINT("PML4 physical address: 0x%llx\n", pml4_pa);

    QWORD* VaPt = NULL, * Va4kb = NULL, * VaPdt = NULL, * VaPdpt = NULL;
    PTE_TABLE Table = { 0 };
    PHYSICAL_ADDRESS LowAddr = { 0 }, HighAddr = { 0 };
    HighAddr.QuadPart = MAXULONG64;

    // 分配连续内存用于新页表
    VaPt = (QWORD*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddr, HighAddr, LowAddr, MmNonCached);
    Va4kb = (QWORD*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddr, HighAddr, LowAddr, MmNonCached);
    VaPdt = (QWORD*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddr, HighAddr, LowAddr, MmNonCached);
    VaPdpt = (QWORD*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddr, HighAddr, LowAddr, MmNonCached);

    if (!VaPt || !Va4kb || !VaPdt || !VaPdpt) {
        if (VaPt) MmFreeContiguousMemory(VaPt);
        if (Va4kb) MmFreeContiguousMemory(Va4kb);
        if (VaPdt) MmFreeContiguousMemory(VaPdt);
        if (VaPdpt) MmFreeContiguousMemory(VaPdpt);
        DEBUG_PRINT("Failed to allocate page table memory\n");
        return false;
    }

    // 初始化分配的内存
    RtlZeroMemory(VaPt, PAGE_SIZE);
    RtlZeroMemory(Va4kb, PAGE_SIZE);
    RtlZeroMemory(VaPdt, PAGE_SIZE);
    RtlZeroMemory(VaPdpt, PAGE_SIZE);

    Table.LineAddress = replaceAlignAddr;
    if (!get_pages_table(&Table)) {
        MmFreeContiguousMemory(VaPt);
        MmFreeContiguousMemory(Va4kb);
        MmFreeContiguousMemory(VaPdt);
        MmFreeContiguousMemory(VaPdpt);
        DEBUG_PRINT("Failed to get page table info\n");
        return false;
    }

    QWORD va = (QWORD)replaceAlignAddr;
    QWORD pml4e_index = (va >> 39) & 0x1FF;
    QWORD pdpte_index = (va >> 30) & 0x1FF;
    QWORD pde_index = (va >> 21) & 0x1FF;
    QWORD pte_index = (va >> 12) & 0x1FF;

    // ============== 关键修复1：正确处理大页分割后的情况 ==============
    if (Table.IsLargePage && splitPDE) {
        MmFreeContiguousMemory(VaPt);//释放申请的小页
        QWORD pt_pa = splitPDE->PageFrameNumber << 12;//pt头部的物理地址
        VaPt = (QWORD*)physical_to_virtual(pt_pa);//获取Pte头虚拟地址
        if (!VaPt) {
            DEBUG_PRINT("Failed to map large page PT: 0x%llx\n", pt_pa);
            goto cleanup;
        }
        DEBUG_PRINT("Using split large page PT: 0x%p (PFN: 0x%llx)\n", VaPt, splitPDE->PageFrameNumber);
    }
    else if (!Table.IsLargePage) {
        QWORD pt_va = (QWORD)Table.PteAddress - pte_index * 8;//原页面Pte头部
        if (!MmIsAddressValid((PVOID)pt_va)) {
            DEBUG_PRINT("Invalid PT virtual address: 0x%p\n", pt_va);
            goto cleanup;
        }
        RtlCopyMemory(VaPt, (void*)pt_va, PAGE_SIZE);//复制整页
    }
    // ============== 修复结束 ==============

    // 复制目标页面内容
    if (!MmIsAddressValid(replaceAlignAddr)) {
        DEBUG_PRINT("Invalid replace address: 0x%p\n", replaceAlignAddr);
        goto cleanup;
    }
    RtlCopyMemory(Va4kb, replaceAlignAddr, PAGE_SIZE);

    // 处理PDE表
    QWORD pde_pa = Table.PdeAddress->PageFrameNumber << 12;
    void* pde_va = physical_to_virtual(pde_pa);
    if (!pde_va || !MmIsAddressValid(pde_va)) {
        DEBUG_PRINT("Failed to map PDE physical address: 0x%llx\n", pde_pa);
        goto cleanup;
    }
    RtlCopyMemory(VaPdt, pde_va, PAGE_SIZE);

    // 处理PDPTE表
    QWORD pdpte_pa = Table.PdpteAddress->PageFrameNumber << 12;
    void* pdpte_va = physical_to_virtual(pdpte_pa);
    if (!pdpte_va || !MmIsAddressValid(pdpte_va)) {
        DEBUG_PRINT("Failed to map PDPTE physical address: 0x%llx\n", pdpte_pa);
        goto cleanup;
    }
    RtlCopyMemory(VaPdpt, pdpte_va, PAGE_SIZE);

    // ============== 关键修复2：正确映射PML4表 ==============
    void* pml4_va = physical_to_virtual(pml4_pa);
    if (!pml4_va || !MmIsAddressValid(pml4_va)) {
        DEBUG_PRINT("Failed to map PML4 physical address: 0x%llx, virtual: 0x%p\n",
            pml4_pa, pml4_va);
        goto cleanup;
    }
    DEBUG_PRINT("Mapped PML4: physical=0x%llx, virtual=0x%p\n", pml4_pa, pml4_va);
    // ============== 修复结束 ==============

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
    _disable();

    QWORD va4kb_pa = virtual_to_physical(Va4kb);
    if (!va4kb_pa) {
        DEBUG_PRINT("Failed to get Va4kb physical address\n");
        _enable();
        KeLowerIrql(oldIrql);
        goto cleanup;
    }

    // ============== 关键修复3：确保新页表正确初始化 ==============
    // 创建新的PTE
    PTE* new_pte = (PTE*)VaPt;
    new_pte[pte_index].AsUlonglong = 0;
    new_pte[pte_index].Present = 1;
    new_pte[pte_index].ReadWrite = 1;
    new_pte[pte_index].PageFrameNumber = va4kb_pa >> 12;

    // 创建新的PDE
    PDE* new_pde = (PDE*)VaPdt;
    new_pde[pde_index].AsUlonglong = 0;
    new_pde[pde_index].Present = 1;
    new_pde[pde_index].ReadWrite = 1;
    new_pde[pde_index].PageFrameNumber = virtual_to_physical(VaPt) >> 12;

    // 创建新的PDPTE
    PDPTE* new_pdpte = (PDPTE*)VaPdpt;
    new_pdpte[pdpte_index].AsUlonglong = 0;
    new_pdpte[pdpte_index].Present = 1;
    new_pdpte[pdpte_index].ReadWrite = 1;
    new_pdpte[pdpte_index].PageFrameNumber = virtual_to_physical(VaPdt) >> 12;

    // 创建新的PML4E
    //其实有点没看懂
    PML4E* new_pml4 = (PML4E*)VaPdpt; // 重用VaPdpt内存
    PML4E* old_pml4 = (PML4E*)pml4_va;//真PML4虚拟地址
    RtlCopyMemory(new_pml4, old_pml4, PAGE_SIZE);

    new_pml4[pml4e_index].AsUlonglong = 0;
    new_pml4[pml4e_index].Present = 1;
    new_pml4[pml4e_index].ReadWrite = 1;
    new_pml4[pml4e_index].PageFrameNumber = virtual_to_physical(VaPdpt) >> 12;

    // ============== 关键修复4：安全刷新TLB ==============
    // 保存当前CR3
    QWORD old_cr3 = __readcr3();

    // 写入新CR3
    QWORD new_cr3 = virtual_to_physical(new_pml4);
    __writecr3(new_cr3);

    // 立即恢复原CR3
    __writecr3(old_cr3);

    // 刷新目标地址的TLB
    invalidate_page(replaceAlignAddr);
    // ============== 修复结束 ==============

    _enable();
    KeLowerIrql(oldIrql);

    DEBUG_PRINT("Page table isolation completed for 0x%p\n", replaceAlignAddr);

    // 释放资源
    MmFreeContiguousMemory(VaPt);
    MmFreeContiguousMemory(Va4kb);
    MmFreeContiguousMemory(VaPdt);
    MmFreeContiguousMemory(VaPdpt);

    return true;

cleanup:
    if (VaPt) MmFreeContiguousMemory(VaPt);
    if (Va4kb) MmFreeContiguousMemory(Va4kb);
    if (VaPdt) MmFreeContiguousMemory(VaPdt);
    if (VaPdpt) MmFreeContiguousMemory(VaPdpt);
    return false;
}

static bool isolate_pages(HANDLE pid, void* iso_address) {
    PEPROCESS Process = NULL;
    KAPC_STATE Apc = { 0 };
    CR3 Cr3 = { 0 };
    PDE splitPDE = { 0 };

    // 获取目标进程
    if (pid != (HANDLE)4) {
        if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &Process))) {
            DEBUG_PRINT("Failed to find process for pid: %d\n", pid);
            return false;
        }
    }
    else {
        Process = PsGetCurrentProcess();
    }

    KeStackAttachProcess(Process, &Apc);

    // 获取正确的CR3值
    Cr3.AsUlonglong = __readcr3();
    DEBUG_PRINT("Current CR3: 0x%llx\n", Cr3.AsUlonglong);
    //对齐方式,去除低12位
    void* AliginIsoAddr = (void*)((QWORD)iso_address & ~0xFFF);
    DEBUG_PRINT("Aligned isolation address: 0x%p\n", AliginIsoAddr);

    PTE_TABLE Table = { 0 };
    Table.LineAddress = AliginIsoAddr;

    if (!get_pages_table(&Table)) {
        KeUnstackDetachProcess(&Apc);
        if (pid != (HANDLE)4) ObDereferenceObject(Process);
        DEBUG_PRINT("Failed to get initial page table info\n");
        return false;
    }

    // 处理大页
    if (Table.IsLargePage) {
        DEBUG_PRINT("Large page detected, splitting...\n");
        if (!split_large_pages(Table.PdeAddress, &splitPDE)) {
            KeUnstackDetachProcess(&Apc);
            if (pid != (HANDLE)4) ObDereferenceObject(Process);
            DEBUG_PRINT("Failed to split large page\n");
            return false;
        }

        //// 分割后刷新页表信息
        //Table.LineAddress = AliginIsoAddr;
        //if (!get_pages_table(&Table)) {
        //    KeUnstackDetachProcess(&Apc);
        //    if (pid != (HANDLE)4) ObDereferenceObject(Process);
        //    DEBUG_PRINT("Failed to refresh page table after split\n");
        //    return false;
        //}
    }

    // 禁用写保护
    UINT64 cr0 = __readcr0();
    UINT64 original_cr0 = cr0;
    __writecr0(cr0 & ~CR0_WP);
    DEBUG_PRINT("CR0 WP disabled (0x%llx)\n", __readcr0());

    bool bSuc = false;
    __try {
        bSuc = isolate_page_table(Cr3, AliginIsoAddr, Table.IsLargePage ? &splitPDE : NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DEBUG_PRINT("Exception during page isolation: 0x%X\n", GetExceptionCode());
        bSuc = false;
    }

    // 恢复写保护
    __writecr0(original_cr0);
    DEBUG_PRINT("CR0 WP restored (0x%llx)\n", __readcr0());

    KeUnstackDetachProcess(&Apc);
    if (pid != (HANDLE)4) ObDereferenceObject(Process);

    return bSuc;
}



static bool mdl_write_memory(void* address, void* buffer, size_t size) {
    __try {
        PMDL pMdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);
        if (!pMdl) {
            DEBUG_PRINT("Failed to allocate MDL for 0x%p\n", address);
            return false;
        }

        MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);

        void* mappedAddress = MmMapLockedPagesSpecifyCache(
            pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        if (!mappedAddress) {
            DEBUG_PRINT("Failed to map locked pages\n");
            MmUnlockPages(pMdl);
            IoFreeMdl(pMdl);
            return false;
        }

        memcpy(mappedAddress, buffer, size);

        MmUnmapLockedPages(mappedAddress, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DEBUG_PRINT("Exception during MDL write at 0x%p\n", address);
        return false;
    }
}

// 修改后的指令长度检测函数
static uint8_t get_instruction_length(void* address) {
    uint8_t* p = (uint8_t*)address;

    // 扩展指令识别
    if (p[0] == 0x0F) {
        if (p[1] == 0x1F) { // NOP 扩展
            if (p[2] == 0x44 && p[3] == 0x00 && p[4] == 0x00) return 5; // nop dword ptr [rax+rax*1+0x0]
            return 3; // 基础 3 字节指令
        }
        if (p[1] == 0x10 || p[1] == 0x11) return 3; // MOVUPS xmm, xmm/m128
        if (p[1] == 0x28 || p[1] == 0x29) return 3; // MOVAPS xmm, xmm/m128
        if (p[1] == 0x2E || p[1] == 0x2F) return 3; // 浮点比较
        if (p[1] == 0x5A || p[1] == 0x5B) return 3; // CVT 指令
        if (p[1] == 0x6F || p[1] == 0x7F) return 3; // MOVDQU/MOVDQA
    }

    if (p[0] == 0x48) {
        if (p[1] == 0x8B) { // MOV r64, r/m64
            if ((p[2] & 0xC0) == 0xC0) return 3; // 寄存器到寄存器
            return 4; // 带偏移的加载
        }
        if (p[1] == 0x89) { // MOV r/m64, r64
            if ((p[2] & 0xC0) == 0xC0) return 3;
            return 4;
        }
        if (p[1] == 0x83) { // ADD/SUB/AND/OR/XOR/CMP r/m64, imm8
            return 4;
        }
        if (p[1] == 0x81) { // ADD/SUB/AND/OR/XOR/CMP r/m64, imm32
            return 7;
        }
        if (p[1] == 0xFF) { // CALL/JMP r/m64
            return 3;
        }
    }

    if (p[0] == 0xE9) return 5; // JMP rel32
    if (p[0] == 0xE8) return 5; // CALL rel32
    if (p[0] == 0xEB) return 2; // JMP rel8

    // REX 前缀指令
    if ((p[0] & 0xF0) == 0x40) {
        if (p[1] == 0x53) return 2; // PUSH rbx
        if (p[1] == 0x55) return 2; // PUSH rbp
        if (p[1] == 0x56) return 2; // PUSH rsi
        if (p[1] == 0x57) return 2; // PUSH rdi
        if (p[1] == 0x5B) return 2; // POP rbx
        if (p[1] == 0x5D) return 2; // POP rbp
        if (p[1] == 0x5E) return 2; // POP rsi
        if (p[1] == 0x5F) return 2; // POP rdi
        if (p[1] == 0x89) return 3; // MOV r/m32, r32
        if (p[1] == 0x8B) return 3; // MOV r32, r/m32
    }

    // 保守策略：无法识别的指令默认为1字节
    return 1;
}

bool pte_hook(HANDLE pid, void** oFuncAddr, void* targetFuncAddr) {
    static bool bFirst = true;
    if (bFirst) {
        DEBUG_PRINT("Initializing PTE hook engine\n");

        m_PTEBase = get_pte_base();
        if (!m_PTEBase) {
            DEBUG_PRINT("Failed to get PTE base address\n");
            return false;
        }

        m_trampLine = (char*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 5, 'Line');
        if (!m_trampLine) {
            DEBUG_PRINT("Failed to allocate trampoline memory\n");
            return false;
        }
        memset(m_trampLine, 0, PAGE_SIZE * 5);
        DEBUG_PRINT("PTE base: 0x%p, Trampoline: 0x%p\n", m_PTEBase, m_trampLine);
        bFirst = false;
    }

    if (m_curHookCount >= MAX_HOOK_COUNT) {
        DEBUG_PRINT("Max hook count reached\n");
        return false;
    }

    PEPROCESS Process = NULL;
    KAPC_STATE Apc = { 0 };
    NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT("Failed to lookup process: PID=0x%p, status=0x%X\n", pid, status);
        return false;
    }

    DEBUG_PRINT("Hooking function: original=0x%p, target=0x%p\n", *oFuncAddr, targetFuncAddr);

    if (!isolate_pages(pid, *oFuncAddr)) {
        DEBUG_PRINT("Page isolation failed for 0x%p\n", *oFuncAddr);
        ObDereferenceObject(Process);
        return false;
    }

    const uint32_t breakBytesLeast = 14;
    const uint32_t trampLineBreakBytes = 20;
    uint32_t uBreakBytes = 0;
    char* TrampLine = m_trampLine + m_trampLineUsed;
    char* JmpAddrStart = (char*)*oFuncAddr;

    // ============== 关键修复1：按指令边界复制 ==============
    uint32_t totalCopied = 0;
    while (totalCopied < breakBytesLeast) {
        uint8_t len = get_instruction_length(JmpAddrStart + totalCopied);
        if (len == 0 || totalCopied + len > 20) {
            DEBUG_PRINT("Invalid instruction at 0x%p\n", JmpAddrStart + totalCopied);
            break;
        }

        // 复制完整指令
        memcpy(TrampLine + totalCopied, JmpAddrStart + totalCopied, len);
        totalCopied += len;

        DEBUG_PRINT("Copied instruction at 0x%p: length=%d, total=%d\n",
            JmpAddrStart + totalCopied - len, len, totalCopied);
    }
    uBreakBytes = totalCopied;
    // ============== 修复结束 ==============

    if (uBreakBytes < breakBytesLeast) {
        DEBUG_PRINT("Warning: Minimal instruction coverage not met (%d/%d)\n", uBreakBytes, breakBytesLeast);
    }

    if (m_trampLineUsed + uBreakBytes + trampLineBreakBytes > PAGE_SIZE * 5) {
        DEBUG_PRINT("Trampoline space exhausted!\n");
        ObDereferenceObject(Process);
        return false;
    }

    // ============== 关键修复2：正确生成跳回代码 ==============
    // 计算原始函数中剩余代码的地址
    QWORD returnAddress = (QWORD)JmpAddrStart + uBreakBytes;

    // 构建跳回指令 (FF 25 [offset] [address])
    BYTE jmpBackCode[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *(QWORD*)(jmpBackCode + 6) = returnAddress;

    // 复制跳回指令到跳板
    memcpy(TrampLine + uBreakBytes, jmpBackCode, sizeof(jmpBackCode));
    // ============== 修复结束 ==============

    char absolutejmpCode[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    *((QWORD*)(absolutejmpCode + 6)) = (QWORD)targetFuncAddr;

    int hookIndex = -1;
    for (int i = 0; i < MAX_HOOK_COUNT; i++) {
        if (m_info[i].pid == 0) {
            hookIndex = i;
            m_info[i].pid = pid;
            m_info[i].oriAddr = JmpAddrStart;

            // 保存实际复制的字节数
            memcpy(m_info[i].oriBytes, JmpAddrStart, uBreakBytes);

            m_curHookCount++;
            DEBUG_PRINT("Hook recorded at index %d\n", i);
            break;
        }
    }

    if (hookIndex == -1) {
        DEBUG_PRINT("No free hook slot available\n");
        ObDereferenceObject(Process);
        return false;
    }

    KeStackAttachProcess(Process, &Apc);
    bool success = mdl_write_memory(JmpAddrStart, absolutejmpCode, uBreakBytes);
    KeUnstackDetachProcess(&Apc);

    if (success) {
        *oFuncAddr = TrampLine;
        m_trampLineUsed += uBreakBytes + sizeof(jmpBackCode);
        DEBUG_PRINT("Hook installed: trampoline at 0x%p, used=%d bytes\n",
            TrampLine, uBreakBytes + sizeof(jmpBackCode));
    }
    else {
        DEBUG_PRINT("Failed to write hook code\n");
    }

    ObDereferenceObject(Process);
    return success;
}

typedef NTSTATUS(*PNT_CREATE_FILE)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength);

static PNT_CREATE_FILE g_OriginNtCreateFile = NULL;

NTSTATUS hook_nt_create_file(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    DEBUG_PRINT("NtCreateFile called\n");

    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
        // 打印文件名
        DEBUG_PRINT("File name: %wZ\n", ObjectAttributes->ObjectName);

        UNICODE_STRING targetFile = RTL_CONSTANT_STRING(L"\\??\\C:\\test.txt");
        if (RtlEqualUnicodeString(ObjectAttributes->ObjectName, &targetFile, TRUE)) {
            DEBUG_PRINT("Blocking access to test.txt\n");
            return STATUS_ACCESS_DENIED;
        }
    }

    return g_OriginNtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength);
}
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DEBUG_PRINT("Driver loaded\n");

    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"NtCreateFile");
    PNT_CREATE_FILE pNtCreateFile = (PNT_CREATE_FILE)MmGetSystemRoutineAddress(&funcName);

    if (!pNtCreateFile) {
        DEBUG_PRINT("Failed to locate NtCreateFile\n");
        return STATUS_UNSUCCESSFUL;
    }

    DEBUG_PRINT("NtCreateFile found at 0x%p\n", pNtCreateFile);

    void* pOriginal = pNtCreateFile;
    if (!pte_hook((HANDLE)4, (void**)&pOriginal, hook_nt_create_file)) {
        DEBUG_PRINT("Failed to hook NtCreateFile\n");
        return STATUS_UNSUCCESSFUL;
    }

    g_OriginNtCreateFile = (PNT_CREATE_FILE)pOriginal;
    DEBUG_PRINT("Hook successful: original function at 0x%p\n", pOriginal);

    DriverObject->DriverUnload = [](PDRIVER_OBJECT DriverObject) {
        DEBUG_PRINT("Driver unloading, cleaning resources...\n");

        for (int i = 0; i < MAX_HOOK_COUNT; i++) {
            if (m_info[i].pid != 0) {
                PEPROCESS Process;
                NTSTATUS status = PsLookupProcessByProcessId(m_info[i].pid, &Process);

                if (NT_SUCCESS(status)) {
                    KAPC_STATE Apc;
                    KeStackAttachProcess(Process, &Apc);

                    DEBUG_PRINT("Restoring hook at 0x%p (PID=%d)\n",
                        m_info[i].oriAddr, m_info[i].pid);

                    if (mdl_write_memory(m_info[i].oriAddr, m_info[i].oriBytes, 14)) {
                        invalidate_page(m_info[i].oriAddr);
                        DEBUG_PRINT("Restore successful\n");
                    }
                    else {
                        DEBUG_PRINT("Restore failed\n");
                    }

                    KeUnstackDetachProcess(&Apc);
                    ObDereferenceObject(Process);
                }

                m_info[i].pid = 0;
                m_curHookCount--;
            }
        }

        if (m_trampLine) {
            ExFreePool(m_trampLine);
            m_trampLine = NULL;
            DEBUG_PRINT("Trampoline memory released\n");
        }

        DEBUG_PRINT("Driver unload completed\n");
        };

    return STATUS_SUCCESS;
}
