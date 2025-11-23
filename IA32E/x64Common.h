#pragma once
#include <wdm.h>
#include <intrin.h>
#include <cstdint>
#pragma pack(push,1)

// 定义页表项的属性
struct Attribute
{
    UINT64 offset1 : 16;
    UINT64 p : 1;
    UINT64 dpl : 2;
    UINT64 s : 1;
    UINT64 type : 4;
    UINT64 unuse : 6;
    UINT64 ist : 2;
    UINT64 selector : 16;
    UINT64 offset2 : 16;
};

typedef struct _IDT_ENTRY64 {

    union hightStruct
    {
        UINT64 lower;
        struct Attribute attribute;
    };
    UINT64 hight;
}IDT_ENTRY64, * PIDT_ENTRY64;
//
typedef struct _IDTR//IDTR是一个寄存器，它存储中断描述符表（IDT）的基地址和界限。
{
    UINT16 limit;//IDT的大小
    UINT64 base;//IDT的起始地址
}IDTR, * PIDTR;
/// <summary>
/// cr4结构体
/// </summary>
typedef union _CR4 {
    UINT64 value;
    struct
    {
        UINT64 VME : 1;
        UINT64 PVI : 1;
        UINT64 TSD : 1;
        UINT64 DE : 1;
        UINT64 PSE : 1;
        UINT64 PAE : 1;
        UINT64 MCE : 1;
        UINT64 PGE : 1;
        UINT64 PCE : 1;
        UINT64 OSFXSR : 1;
        UINT64 OSXMMEXCPT : 1;
        UINT64 UMIP : 1;
        UINT64 LA57 : 1;
        UINT64 VMXE : 1;
        UINT64 SMXE : 1;
        UINT64 unuse1 : 1;
        UINT64 FSGSBASE : 1;
        UINT64 PCIDE : 1;
        UINT64 OSXSAVE : 1;
        UINT64 KL : 1;
        UINT64 SMEP : 1;
        UINT64 SMAP : 1;
        UINT64 PKE : 1;
        UINT64 CET : 1;
        UINT64 PKS : 1;
        UINT64 Ressrved : 63 - 24;
    }Fields;
}CR4, * PCR4;

static_assert(sizeof(CR4) == 8, "sizeof CR4");
/// <summary>
/// cr3结构体
/// </summary>
//ignore1: 忽略字段
//PWT: Page Write-Through，即页写透
//PCD: Page Cache Disable，即页缓存禁止
//ignore2: 忽略字段
//PPN: Page Physical Number，即物理页号，物理基地址PML4E基地址

typedef union _CR3 {
    UINT64 value;
    struct
    {
        UINT64 ignore1 : 3;
        UINT64 PWT : 1;
        UINT64 PCD : 1;
        UINT64 ignore2 : 7;
        UINT64 PPN : 40;//PML4E物理地址（页号）
        UINT64 Reserved1 : 12;
    }Fields;

}CR3, * PCR3;
static_assert(sizeof(CR3) == 8, "sizeof CR3");

// 各页表项结构体
//PPO：Page Offset，即页内偏移
//PPN：Page Physical Number，即物理页号
//UnUse1: 未使用字段，忽略字段
//物理地址结构体

typedef union _PA {
    UINT64 vaule;
    LARGE_INTEGER AsLargeInteger;//使用 LARGE_INTEGER 类型表示物理地址，便于与 Windows 内核的其他部分交互。
    struct
    {
        UINT64 PPO : 12;//页内偏移
        UINT64 PPN : 40;//物理地址（页号）
        UINT64 UnUse1 : 12;//未使用
    }Fileds4KB;//适用于 4KB 页面大小的物理地址字段,PTE

    struct
    {
        UINT64 PPO : 21;
        UINT64 PPN : 31;
        UINT64 UnUse1 : 12;
    }Fileds2MB;//2MB

    struct
    {
        UINT64 PPO : 30;
        UINT64 PPN : 22;
        UINT64 UnUse1 : 12;
    }Fileds1GB;//1GB

}PA, * P_PA;
static_assert(sizeof(PA) == 8, "sizeof PA");

/// <summary>
/// 虚拟地址结构体
/// </summary>
typedef union _VA {
    UINT64 value;
    LARGE_INTEGER AsLargeInteger;
    struct
    {
        UINT64 VPO : 12;
        UINT64 VPN4 : 9;
        UINT64 VPN3 : 9;
        UINT64 VPN2 : 9;
        UINT64 VPN1 : 9;
        UINT64 UnUse1 : 16;
    }Fileds4KB;

    struct
    {
        UINT64 VPO : 21;
        UINT64 VPN3 : 9;
        UINT64 VPN2 : 9;
        UINT64 VPN1 : 9;
        UINT64 UnUse1 : 16;
    }Fileds2MB;

    struct
    {
        UINT64 VPO : 30;
        UINT64 VPN2 : 9;
        UINT64 VPN1 : 9;
        UINT64 UnUse1 : 16;
    }Fileds1GB;


}VA, * P_VA;
static_assert(sizeof(VA) == 8, "sizeof VA");//用于在编译过程中检查某些条件是否成立。如果条件不成立，编译器会生成一个错误，并输出指定的错误消息。
//第一级页表项结构体
//PML4E
typedef union _PML4E {
    UINT64 value;
    struct
    {
        UINT64 P : 1;
        UINT64 R_W : 1;
        UINT64 US : 1;
        UINT64 PWT : 1;
        UINT64 PCD : 1;
        UINT64 A : 1;
        UINT64 ign : 5;
        UINT64 R : 1;
        UINT64 PPN : 36;
        UINT64 ign2 : 15;
        UINT64 XD : 1;
    }Fields4K;
}PML4E, * PPML4E, L1PTE, * PL1PTE;
static_assert(sizeof(PML4E) == 8, "sizeof PML4E");
// 该代码行用于静态断言，验证 PML4E 的大小是否为 8 字节。
//静态断言，用于在编译时验证条件，确保类型或数据的大小符合预期
//
typedef union _PDPTE {
    UINT64 value;
    struct
    {
        UINT64 P : 1;
        UINT64 R_W : 1;
        UINT64 US : 1;
        UINT64 PWT : 1;
        UINT64 PCD : 1;
        UINT64 A : 1;
        UINT64 ign : 1;
        UINT64 PS : 1;
        UINT64 ign2 : 3;
        UINT64 R : 1;
        UINT64 PPN : 36;
        UINT64 ign3 : 15;
        UINT64 XD : 1;
    }Fields4K;

    struct
    {
        UINT64 P : 1;
        UINT64 R_W : 1;
        UINT64 US : 1;
        UINT64 PWT : 1;
        UINT64 PCD : 1;
        UINT64 A : 1;
        UINT64 Dirty : 1;
        UINT64 PS : 1;
        UINT64 G : 1;
        UINT64 ign2 : 2;
        UINT64 R : 1;
        UINT64 PAT : 1;
        UINT64 Reserved : 17;
        UINT64 PPN : 18;
        UINT64 Reserved_2 : 4;
        UINT64 ign3 : 7;
        UINT64 protection_key : 4;
        UINT64 XD : 1;
    }Fields1G;

}PDPTE, * PPDPTE, L2PTE, * PL2PTE;
static_assert(sizeof(PDPTE) == 8, "sizeof PDPTE");
//
typedef union _PDE {
    UINT64 value;
    struct
    {
        UINT64 P : 1;
        UINT64 R_W : 1;
        UINT64 US : 1;
        UINT64 PWT : 1;
        UINT64 PCD : 1;
        UINT64 A : 1;
        UINT64 ign : 1;
        UINT64 PS : 1;
        UINT64 ign2 : 3;
        UINT64 R : 1;
        UINT64 PPN : 36;
        UINT64 ign3 : 15;
        UINT64 XD : 1;
    }Fields4K;

    struct
    {
        UINT64 P : 1;
        UINT64 R_W : 1;
        UINT64 US : 1;
        UINT64 PWT : 1;
        UINT64 PCD : 1;
        UINT64 A : 1;
        UINT64 Dirty : 1;
        UINT64 PS : 1;//large_page
        UINT64 G : 1;
        UINT64 ign2 : 2;
        UINT64 R : 1;
        UINT64 PAT : 1;
        UINT64 Reserved : 8;
        UINT64 PPN : 27;
        UINT64 Reserved_2 : 4;
        UINT64 ign3 : 7;
        UINT64 protection_key : 4;
        UINT64 XD : 1;
    }Fields2MB;

}PDE, * PPDE, L3PTE, * PL3PTE;

static_assert(sizeof(PDE) == 8, "sizeof PDE");
//
typedef union _PTE {
    UINT64 value;
    struct
    {
        UINT64 P : 1;
        UINT64 R_W : 1;
        UINT64 US : 1;
        UINT64 PWT : 1;
        UINT64 PCD : 1;
        UINT64 A : 1;
        UINT64 Dirty : 1;//D
        UINT64 PAT : 1;
        UINT64 G : 1;
        UINT64 ign2 : 2;
        UINT64 R : 1;
        UINT64 PPN : 36;
        UINT64 Reserved : 4;
        UINT64 ign3 : 7;
        UINT64 protection_key : 4;
        UINT64 XD : 1;
    }Fields4K;

}PTE, * PPTE, L4PTE, * PL4PTE;
static_assert(sizeof(PTE) == 8, "sizeof PTE");





typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved_1 : 1;
        uint64_t must_be_zero : 1;
        uint64_t ignored_1 : 3;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pml4e_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 2;
        uint64_t restart : 1;
        uint64_t pat : 1;
        uint64_t reserved_1 : 17;
        uint64_t page_frame_number : 18;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pdpte_1gb_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved_1 : 1;
        uint64_t large_page : 1;
        uint64_t ignored_1 : 3;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pdpte_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 2;
        uint64_t restart : 1;
        uint64_t pat : 1;
        uint64_t reserved_1 : 8;
        uint64_t page_frame_number : 27;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pde_2mb_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved_1 : 1;
        uint64_t large_page : 1;
        uint64_t ignored_1 : 3;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pde_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t pat : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 2;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_1 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pte_64;

typedef union {
    struct {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 2;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_1 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };

    uint64_t flags;
} pt_entry_64;

#pragma pack(pop)

/**
 * @defgroup paging_structures_entry_count_64 \
 *           Paging structures entry counts
 * @{
 */
//#define PML4_ENTRY_COUNT_64                                          0x00000200
//#define PDPTE_ENTRY_COUNT_64                                         0x00000200
//#define PDE_ENTRY_COUNT_64                                           0x00000200
//#define PTE_ENTRY_COUNT_64                                           0x00000200
////各个页表存储了512个页表项
//#define MIX_PAGETABLEENTRY_SIZE 512
//------内核导出函数声明：begin------//
//extern PVOID __stdcall MmGetVirtualForPhysical(LARGE_INTEGER AsLargeInteger);//物理地址转虚拟地址
//extern LARGE_INTEGER __stdcall MmGetPhysicalForVirtual(PVOID VirtualAddress); //虚拟地址转物理地址
//extern NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);//根据进程ID获取进程对象
//------内核导出函数声明: end------//

//声明