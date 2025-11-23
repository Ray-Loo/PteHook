#include <ntifs.h>
#include <wdm.h>
#include <intrin.h>
#include "hde/hde64.h"
#include "PageTable.h"
#include "rewrite.h"

#define _HOOK_ALL_COUNT_ 24ull    //最大可以Hook24个
#define _TRAMPOLINE_SIZE_ 42ull   //每个跳板大小为42字节
static PHOOK_PROCESS_INFO g_pHookProcessInfo = NULL;

//初始化Hook信息结构体
BOOLEAN InitilizeHookInfo(PWCHAR pwcProcessName)
{
    //传入进程名，返回目标进程的EPROCESS指针
    PEPROCESS Eprocess = GetProcessByName(pwcProcessName);
    if (!Eprocess)
    {
        return STATUS_ACCESS_DENIED;
    }

    //分配Hook结构体
    g_pHookProcessInfo = (PHOOK_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_PROCESS_INFO), 'Info');
    if (!g_pHookProcessInfo)
    {
        //解除GetProcessByName函数中PsLookupProcessByProcessId对内核对象EPROCESS的引用
        ObDereferenceObject(g_pHookProcessInfo->pEprocess);
        return FALSE;
    }
    memset(g_pHookProcessInfo, 0, sizeof(HOOK_PROCESS_INFO));

    //分配4Kb页面，用于存放跳板
    g_pHookProcessInfo->pulTrampoline = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, '0etP');
    if (!g_pHookProcessInfo->pulTrampoline)
    {
        ExFreePoolWithTag(g_pHookProcessInfo, 'Info');
        //解除GetProcessByName函数中PsLookupProcessByProcessId对内核对象EPROCESS的引用
        ObDereferenceObject(g_pHookProcessInfo->pEprocess);
        return FALSE;
    }
    RtlZeroMemory(g_pHookProcessInfo->pulTrampoline, PAGE_SIZE);

    g_pHookProcessInfo->pEprocess = Eprocess;

    return TRUE;
}

//安装PTE Hook的函数主体
//参数ProcessId进程PID
//参数OriginToTrampoline指向HOOK目标函数指针的指针，用于返回跳板基址
//参数HandlerAddress自定义的HOOK函数
//参数PatchSize需要HOOK的字节数
ULONG_PTR SetupPageTableHook(PWCHAR pwcProcessName, PUCHAR* OriginToTrampoline, PVOID HandlerAddress)
{
    ULONG_PTR ulRet = 0;
    ULONG64 PatchSize = 0;       //Hook破坏的字节
    ULONG64 ulFuncAddrTemp = (ULONG64)(*OriginToTrampoline);

    //  DbgBreakPoint();
    if (!pwcProcessName || !HandlerAddress)
    {
        return ulRet;
    }
    //初始化结构体
    if (!g_pHookProcessInfo)
    {
        InitilizeHookInfo(pwcProcessName);
    }

    if (!g_pHookProcessInfo->pEprocess)
    {
        return ulRet;
    }
    //判断是否超过了总Hook数量
    if (g_pHookProcessInfo->ulHookNumber >= _HOOK_ALL_COUNT_ ||
        !MmIsAddressValid(g_pHookProcessInfo) || !MmIsAddressValid(g_pHookProcessInfo->pulTrampoline))
    {
        //解除GetProcessByName函数中PsLookupProcessByProcessId对内核对象EPROCESS的引用
        ObDereferenceObject(g_pHookProcessInfo->pEprocess);
        return ulRet;
    }

    //===================页表隔离========================
    //传入进程结构体和需要Hook的线性地址，自建页表，将目标函数基址映射到原页表中
    if (!KeReplacePageTable(g_pHookProcessInfo->pEprocess, (ULONG_PTR)*OriginToTrampoline))
    {
        //解除GetProcessByName函数中PsLookupProcessByProcessId对内核对象EPROCESS的引用
        ObDereferenceObject(g_pHookProcessInfo->pEprocess);
        return ulRet;
    }

    //反汇编类 计算目标函数头被破坏的字节数
    hde64s hde = { 0 };
    while (PatchSize < 14)
    {
        //传入起始地址，返回结构体
        hde64_disasm((PVOID)(ulFuncAddrTemp + PatchSize), &hde);
        PatchSize += hde.len; //hde.len是当前行汇编所占的字节
    }

    //     //传入目标函数地址，破坏字节数。创建返回跳板偏移
    ulRet = CreateTrampoline(ulFuncAddrTemp, PatchSize);
    if (!ulRet)
    {
        //解除GetProcessByName函数中PsLookupProcessByProcessId对内核对象EPROCESS的引用
        ObDereferenceObject(g_pHookProcessInfo->pEprocess);
        return ulRet;
    }

    //Hook目标函数
    ulRet = SetOriginAddressJmpHandlerAddress(g_pHookProcessInfo->pEprocess, (PVOID)ulFuncAddrTemp, HandlerAddress);

    //解除GetProcessByName函数中PsLookupProcessByProcessId对内核对象EPROCESS的引用
    ObDereferenceObject(g_pHookProcessInfo->pEprocess);

    return ulRet;
}

//传入进程EPROCESS，传入对齐物理页的目标函数地址，重建目标函数所在的页表
BOOLEAN KeReplacePageTable(PEPROCESS Process, ULONG_PTR pucFuncAddr)
{
    KAPC_STATE Apc = { 0 };
    KeStackAttachProcess(Process, &Apc);
    BOOLEAN IsSuccess = FALSE;

    while (TRUE)
    {
        PAGE_TABLE PageTable = { 0 };
        //物理页面对齐，即物理页首地址
        PageTable.ulLinearAlignAddress = (ULONG_PTR)PAGE_ALIGN(pucFuncAddr);
        //通过目标函数的地址，获取目标地址的Pte,Pde,Pdpte,Pml4e的虚拟地址，存入PageTable结构中
        if (!GetPageTable(&PageTable)) return 0;
        ULONG_PTR ulPtePa = *(PULONG_PTR)(PageTable.ulPteVa);
        ULONG_PTR ulPdePa = *(PULONG_PTR)(PageTable.ulPdeVa);

        //判断目标函数地址标记 第7位PS==0 是否为大页
        if (ulPdePa & 0x80)
        {
            //传入Pde物理地址，手动分割Pde大页的物理地址，存放在自建的Pte表中
            PULONG_PTR pPtVa = SplitLargePage(ulPdePa);
            if (!pPtVa)
            {
                Logger(FALSE, "SplitLargePage Return False!", 0);
                break;
            }
            //插入自建页表到相应的页表中
            IsSuccess = IsolationPageTable(&PageTable, pPtVa);
            if (!IsSuccess)
            {
                Logger(FALSE, "BigPage IsolationPageTable Return False!", 0);
                break;
            }
            //修复全局的Pde的物理地址中G位
            if (ulPdePa & 0x100)
            {
                *(PULONG_PTR)(PageTable.ulPdeVa) = ulPdePa & (~0x100);
            }
        }
        else
        {
            //插入自建页表到相应的页表中
            IsSuccess = IsolationPageTable(&PageTable, NULL);
            if (!IsSuccess)
            {
                Logger(FALSE, "IsolationPageTable Return False!", 0);
                break;
            }
            //修复全局的Pte的物理地址中G位
            if (ulPtePa & 0x100)
            {
                *(PULONG_PTR)(PageTable.ulPteVa) = ulPtePa & (~0x100);
            }
        }
        IsSuccess = TRUE;
        break;
    }
    KeUnstackDetachProcess(&Apc);

    return IsSuccess;
}

//Pde是2m大页，则传入该大页Pde中存放的物理地址，对Pte进行重新分割，返回Pde的虚拟地址
PULONG_PTR SplitLargePage(ULONG_PTR ulBigPagePdePa)
{
    //分配4Kb的Pte页表,KeAllocateContiguousMemorySpecifyCache是分配连续的非分页物理内存
    PULONG_PTR pulPteVa = (PULONG_PTR)KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmCached);
    if (!pulPteVa)
    {
        return pulPteVa;
    }
    //找到目标函数所在的Pde的物理基地址，以下2m的物理地址为一个大页
    ULONG_PTR PdePageFrameNumber = ulBigPagePdePa;
    //去掉标记位
    PdePageFrameNumber = PdePageFrameNumber & 0x000ffffffffff000;
    //循环分割拷贝大页中各个Pte物理地址到自建的pdt中
    for (ULONG64 i = 0; i < 512; i++)
    {
        //  pulPteVa[i] = ulBigPagePdePa & 0x7f;    //只要原来pde中的最后7位，其它位都清0？？？？？？？？？？？
        pulPteVa[i] = ulBigPagePdePa & 0xFFF0000000000FFF;

        //设置Pte属性的第8位G==0   TLB不刷新
        pulPteVa[i] = pulPteVa[i] & (~0x100);

        //设置Pte属性的第1位P==1   有效
        //设置Pte属性的第2位R/W==1 读写
        //pulPteVa[i] = pulPteVa[i] | 0x3;

        //拷贝pde大页中,每个0x1000字节的物理地址到各个自建的Pte中
        pulPteVa[i] |= (PdePageFrameNumber + i * 0x1000);
    }

    return pulPteVa;
}

//开始进行页表隔离，传入PageTable结构体，Pde大页时自建的虚拟地址
BOOLEAN IsolationPageTable(PPAGE_TABLE pPageTable, PULONG64 PdeToPt_Va)
{
    ULONG_PTR ulPhysicalTemp = 0;
    PULONG_PTR pulVirtualTemp = 0;
    ULONG icount = 0ul;
    PVOID Address4kbVa = 0;
    PVOID PtVa = 0;
    PVOID PdtVa = 0;
    PVOID PdptVa = 0;
    //获取目标地址在4个页表中的索引
    ULONG64 Pml4eIndex = (pPageTable->ulLinearAlignAddress & 0x0000FF8000000000) >> 39;
    ULONG64 PdpteIndex = (pPageTable->ulLinearAlignAddress & 0x0000007FC0000000) >> 30;
    ULONG64 PdeIndex = (pPageTable->ulLinearAlignAddress & 0x000000003FE00000) >> 21;
    ULONG64 PteIndex = (pPageTable->ulLinearAlignAddress & 0x00000000001FF000) >> 12;

    //线性地址保存
    g_pHookProcessInfo->PteInfoList[g_pHookProcessInfo->ulHookNumber].LinearAddress = pPageTable->ulLinearAlignAddress;
    //判断目标PageTable中哪个表不需要分配。

    //分配4张页表的虚拟地址空间
    //4Kb的虚拟地址如果已经隔离，则该虚拟地址有值。
    Address4kbVa = KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmCached);
    if (!Address4kbVa && !MmIsAddressValid(Address4kbVa))
    {
        DbgPrintEx(77, 0, "[cf]:The PageTable 4kb Virtual Invalid!");
        return FALSE;
    }
    //PageTable结构中存放的LinearAddress是LinearAddress的基址
    RtlCopyMemory(Address4kbVa, (PUCHAR)(pPageTable->ulLinearAlignAddress), PAGE_SIZE);
    g_pHookProcessInfo->PteInfoList[g_pHookProcessInfo->ulHookNumber].ulNewAddress4kbVA = Address4kbVa;

    if (!PdeToPt_Va)
    {
        //没有传入自建Pte，分配内存
        PtVa = KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmCached);
        if (!PtVa && !MmIsAddressValid(PtVa))
        {
            if (Address4kbVa)
            {
                MmFreeContiguousMemory(Address4kbVa);
                Address4kbVa = 0;
            }
            DbgPrintEx(77, 0, "[cf]:The PageTable PtVa Virtual Invalid!");
            return FALSE;
        }
        //PageTable结构中存放的目标函数的 Pte - 索引 * 8 = 函数所在的Pte的基址
        RtlCopyMemory(PtVa, (PUCHAR)(pPageTable->ulPteVa - PteIndex * 8), PAGE_SIZE);
    }
    else
    {
        //Pte表，传入的第2个参数（即2m大页拆分的自建）
        PtVa = PdeToPt_Va;//此时指向Pte表头
    }
    g_pHookProcessInfo->PteInfoList[g_pHookProcessInfo->ulHookNumber].ulNewPteVA = PtVa;

    PdtVa = KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmCached);//pde表虚拟地址
    if (!PdtVa && !MmIsAddressValid(PdtVa))
    {
        if (Address4kbVa)
        {
            MmFreeContiguousMemory(Address4kbVa);
            Address4kbVa = 0;
        }
        if (PtVa)
        {
            MmFreeContiguousMemory(PtVa);
            PtVa = 0;
        }
        DbgPrintEx(77, 0, "[cf]:The PageTable PdtVa Virtual Invalid!");
        return FALSE;
    }
    //PageTable结构中存放的目标函数的 Pde - 索引 * 8 = 函数所在的Pde的基址。即向前追溯到该表的表头
    RtlCopyMemory(PdtVa, (PUCHAR)(pPageTable->ulPdeVa - PdeIndex * 8), PAGE_SIZE);//复制所有pde表项
    g_pHookProcessInfo->PteInfoList[g_pHookProcessInfo->ulHookNumber].ulNewPdtVA = PdtVa;//记录

    PdptVa = KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmCached);//pdpt表
    if (!PdptVa && !MmIsAddressValid(PdptVa))
    {
        if (Address4kbVa)
        {
            MmFreeContiguousMemory(Address4kbVa);
            Address4kbVa = 0;
        }
        if (PtVa)
        {
            MmFreeContiguousMemory(PtVa);
            PtVa = 0;
        }
        if (PdtVa)
        {
            MmFreeContiguousMemory(PdtVa);
            PdtVa = 0;
        }
        DbgPrintEx(77, 0, "[cf]:The PageTable PdptVa Virtual Invalid!");
        return FALSE;
    }
    //拷贝目标页表中的原数据到新分配的空间
    //PageTable结构中存放的目标函数的 Pdpte - 索引 * 8 = 函数所在的Pdpte的基址。即向前追溯到该表的表头
    RtlCopyMemory(PdptVa, (PUCHAR)(pPageTable->ulPdpteVa - PdpteIndex * 8), PAGE_SIZE);
    g_pHookProcessInfo->PteInfoList[g_pHookProcessInfo->ulHookNumber].ulNewPdptVA = PdptVa;


    //替换页表指向
    //暂时禁用正常内核 APC 的执行，但不阻止特殊内核 APC 运行。
    KeEnterCriticalRegion();//此时并不是提升irql而是禁用apc
    KIRQL kIrql = 0;
    ULONG_PTR ulCr4 = 0;//设置Cr4的第23位，开启WP强写
    Cr0_wp_Bit_Off(&kIrql, &ulCr4);//大概率是提升IRQL并且修改CR4
    /*  _disable();*/


            //取自建Address4kbVa的物理地址，复制到PteVa页表中相应的PteIndex项中，
    ulPhysicalTemp = MmVaToPa(Address4kbVa);//获取伪造物理页物理地址
    pulVirtualTemp = &((PULONG_PTR)PtVa)[PteIndex];

    //将原页面的物理地址标志位，复制到替换页的物理地址上
    ulPhysicalTemp &= 0x000FFFFFFFFFF000;
    ulPhysicalTemp |= ((*pulVirtualTemp) & 0xFFF0000000000FFF);

    //将Pte的G位TLB刷新位改为0
    if (ulPhysicalTemp & 0x100)
    {
        ulPhysicalTemp = ulPhysicalTemp & ~0x100;       //设置标志位1111 1111 1111 1111 1111 1110 1111 1111
    }
    ulPhysicalTemp = ulPhysicalTemp | 0x13;     //设置标志位0001 0011

    //替换页表中对应的项，隔离。
    *pulVirtualTemp = ulPhysicalTemp;

    //自建PtVa复制到PdeVa页表中相应的PdeIndex项中，设置符号拓展位和标志位
    ulPhysicalTemp = MmVaToPa(PtVa);
    pulVirtualTemp = &((PULONG_PTR)PdtVa)[PdeIndex];

    //将原页面的物理地址标志位，复制到替换页的物理地址上
    ulPhysicalTemp &= 0x000FFFFFFFFFF000;
    ulPhysicalTemp |= ((*pulVirtualTemp) & 0xFFF0000000000FFF);
    //将Pte的G位TLB刷新位改为0
    if ((ulPhysicalTemp) & 0x100)
    {
        ulPhysicalTemp = ulPhysicalTemp & ~0x100;       //设置标志位1111 1111 1111 1111 1111 1110 1111 1111
    }
    //将Pde的大页位改为0
    if ((ulPhysicalTemp) & 0x80)
    {
        ulPhysicalTemp = ulPhysicalTemp & ~0x80;        //设置标志位1111 1111 1111 1111 1111 1111 0111 1111
    }
    //有效，可读写
    ulPhysicalTemp = ulPhysicalTemp | 0x13;     //设置标志位0001 0011

    //替换页表中对应的项，隔离。
    *pulVirtualTemp = ulPhysicalTemp;

    //自建PdtVa复制到PdpteVa页表中相应的PdpteIndex项中，设置符号拓展位和标志位
    ulPhysicalTemp = MmVaToPa(PdtVa);
    pulVirtualTemp = &((PULONG_PTR)PdptVa)[PdpteIndex];

    //将原页面的物理地址标志位，复制到替换页的物理地址上
    ulPhysicalTemp &= 0x000FFFFFFFFFF000;
    ulPhysicalTemp |= ((*pulVirtualTemp) & 0xFFF0000000000FFF);

    ulPhysicalTemp = ulPhysicalTemp | 0x13;     //设置标志位0000 0011

    //替换页表中对应的项，隔离。
    *pulVirtualTemp = ulPhysicalTemp;

    //获取Pml4t表虚拟地址
    ULONG_PTR paCr3 = __readcr3();
    paCr3 &= 0x000FFFFFFFFFF000;
    PULONG_PTR Pml4tVa = MmPaToVa(paCr3);
    if (!Pml4tVa) return FALSE;

    //自建PdptVa复制到Pml4eVa页表中相应的Pml4eIndex项中，设置符号拓展位和标志位
    ulPhysicalTemp = MmVaToPa(PdptVa);
    pulVirtualTemp = &Pml4tVa[Pml4eIndex];//获取Pml4e表项的虚拟地址
    //先保存原始的物理地址和该地址在页表中的线性地址
    g_pHookProcessInfo->PteInfoList[g_pHookProcessInfo->ulHookNumber].ulOriPxeVA = (ULONG_PTR)pulVirtualTemp;       //保存页表中目标存放的线性地址
    g_pHookProcessInfo->PteInfoList[g_pHookProcessInfo->ulHookNumber].ulOriPxePA = *pulVirtualTemp;             //保存需要隔离的页表的物理地址

    //将原页面的物理地址标志位，复制到替换页的物理地址上
    ulPhysicalTemp &= 0x000FFFFFFFFFF000;//清除地址位
    ulPhysicalTemp |= ((*pulVirtualTemp) & 0xFFF0000000000FFF);//添加地址位

    ulPhysicalTemp = ulPhysicalTemp | 0x13;     //添加标志位0000 0011
    ulPhysicalTemp = ulPhysicalTemp | 0x70;     //??为什么要改0x70??

    //替换页表中对应的项，隔离。
    *pulVirtualTemp = ulPhysicalTemp;//指向的项目替换

    __invlpg((PVOID)pPageTable->ulLinearAlignAddress);   //刷新TLB，使TLB缓冲区失效。
    //  _enable();
    Cr0_wp_Bit_On(kIrql, ulCr4);//关WP

    KeLeaveCriticalRegion();    //开APC

    return TRUE;

}

//创建一个Hook完成后 返回源函数的跳板基址
ULONG64 CreateTrampoline(ULONG64 OriginAddress, ULONG64 PatchSize)
{
    //跳板的起始地址
    ULONG64 ulTampoOffset = g_pHookProcessInfo->pulTrampoline + (g_pHookProcessInfo->ulHookNumber * _TRAMPOLINE_SIZE_);

    //返回原函数的ShallCode       20字节
    UCHAR TrampolineCode[] =
    {
        0x6A,0x00,                                          // push 0
        0x36,0xC7,0x04,0x24 ,0x00,0x00,0x00,0x00,         // mov dword ptr ss : [rsp] , 0x00
        0x36,0xC7,0x44,0x24 ,0x04 ,0x00,0x00,0x00,0x00,       // mov dword ptr ss : [rsp + 4] , 0x00
        0xC3                                                // ret
    };

    //修改返回地址
    *(PUINT32)&TrampolineCode[6] = (UINT32)((OriginAddress + PatchSize) & 0xFFFFFFFF);
    *(PUINT32)&TrampolineCode[15] = (UINT32)(((OriginAddress + PatchSize) >> 32) & 0xFFFFFFFF);

    //保存Hook破坏的原函数代码到跳板中
    RtlCopyMemory(ulTampoOffset, (PUCHAR)OriginAddress, PatchSize);
    //保存ShallCode到跳板代码中，用于Hook完成后返回
    RtlCopyMemory(ulTampoOffset + PatchSize, TrampolineCode, sizeof(TrampolineCode));

    //返回跳板基址
    return ulTampoOffset;
}

//Hook源函数，传入源函数所在进程Process，源函数基址OriginAddress，自建Hook函数基址HandlerAddress
ULONG_PTR SetOriginAddressJmpHandlerAddress(PEPROCESS Process, PVOID OriginAddress, PVOID HandlerAddress)
{
    KAPC_STATE ApcState = { 0 };
    KeStackAttachProcess(Process, &ApcState);
    ULONG_PTR ulFuncAddrTemp = 0;
    UCHAR JmpCode[] =
    {
        0xFF,0x25,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    *(PULONG_PTR*)&JmpCode[6] = (PULONG_PTR)HandlerAddress;

    //  BOOLEAN R = KeMdlCopyMemory(OriginAddress, JmpCode, sizeof(JmpCode));
    //给定缓冲区的起始地址和长度，分配足够大的内存描述符列表（MDL）来映射缓冲区。
    PMDL Mdl = IoAllocateMdl(OriginAddress, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!Mdl)
    {
        Logger(FALSE, "MmProtectMdlSystemAddress False!", 0);
        return ulFuncAddrTemp;
    }

    //接收指定非分页虚拟内存缓冲区的 MDL，并对其进行更新以描述基础物理页。
    //MmGetSystemAddressForMdlSafe 先进行锁定 MmProbeAndLockPages、mmBuildMdlForNonPagedPool、IoBuildPartialMdl或 mmAllocatePagesForMdlEx    释放用MmUnlockPages
    __try {
        MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger(TRUE, "MmMapLockedPagesSpecifyCache False!", 0);
    }
    //映射到虚拟内存，访问模式KernelMode，缓存模式MmCached，页保护模式NormalPagePriority
    PVOID fAddress = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    //  PVOID fAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    if (!fAddress)
    {
        Logger(TRUE, "MmMapLockedPagesSpecifyCache False!", STATUS_NO_MEMORY);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return ulFuncAddrTemp;
    }
    //设置内存地址范围的保护类型。
    NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);
    if (NT_ERROR(Status))
    {
        Logger(TRUE, "MmProtectMdlSystemAddress False!", Status);
        MmUnmapLockedPages(fAddress, Mdl);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return ulFuncAddrTemp;
    }

    KeEnterCriticalRegion();//暂时禁用正常内核 APC 的执行，但不阻止特殊内核 APC 运行。
    KIRQL kIrql = 0;
    ULONG_PTR ulCr4 = 0;//设置Cr4的第23位，开启WP强写
    Cr0_wp_Bit_Off(&kIrql, &ulCr4);
    //  _disable();
    RtlMoveMemory(fAddress, JmpCode, sizeof(JmpCode));    //拷贝数据到目标地址
    //  _enable();
    Cr0_wp_Bit_On(kIrql, ulCr4);//关WP
    KeLeaveCriticalRegion();//开启APC执行

    //解锁
    MmUnmapLockedPages(fAddress, Mdl);
    MmUnlockPages(Mdl);
    //释放MDL
    IoFreeMdl(Mdl);

    KeUnstackDetachProcess(&ApcState);

    //将跳板基址传给局变量（该变量原存放目标函数地址）
    ulFuncAddrTemp = (ULONG_PTR)(g_pHookProcessInfo->pulTrampoline + (g_pHookProcessInfo->ulHookNumber * _TRAMPOLINE_SIZE_));
    //Hook数量+1
    g_pHookProcessInfo->ulHookNumber += 1;

    return ulFuncAddrTemp;
}

VOID UnLoadPteHook()
{
    DbgBreakPoint();
    KAPC_STATE Apc = { 0 };
    KeStackAttachProcess(g_pHookProcessInfo->pEprocess, &Apc);

    KeEnterCriticalRegion();    //暂时禁用正常内核 APC 的执行，但不阻止特殊内核 APC 运行。
    _disable();                 //关中断

    //先恢复pte页的页表指向
    for (ULONG ulcount = 0ul; ulcount < g_pHookProcessInfo->ulHookNumber; ulcount++)
    {
        if ((g_pHookProcessInfo->PteInfoList[ulcount].ulOriPxeVA) && (g_pHookProcessInfo->PteInfoList[ulcount].ulOriPxePA))
        {
            //替换页表指向
            *(PULONG64)(g_pHookProcessInfo->PteInfoList[ulcount].ulOriPxeVA) = g_pHookProcessInfo->PteInfoList[ulcount].ulOriPxePA;
            //          __invlpg((PULONG64)(g_pHookProcessInfo->PteInfoList[ulcount].LinearAddress));    //刷新TLB，使TLB缓冲区失效。
        }
    }

    KIRQL kIrql = KeRaiseIrqlToDpcLevel();   //提升IRQL到DPC
    //遍历分配的页表，释放
    for (ULONG i = 0ul; i < g_pHookProcessInfo->ulHookNumber; i++)
    {
        if (g_pHookProcessInfo->PteInfoList[i].ulNewAddress4kbVA)
        {
            //释放4kb页面
            MmFreeContiguousMemory((PVOID)g_pHookProcessInfo->PteInfoList[i].ulNewAddress4kbVA);
            g_pHookProcessInfo->PteInfoList[i].ulNewAddress4kbVA = 0;
        }
        if (g_pHookProcessInfo->PteInfoList[i].ulNewPteVA)
        {
            //释放pte页面
            MmFreeContiguousMemory((PVOID)g_pHookProcessInfo->PteInfoList[i].ulNewPteVA);
            g_pHookProcessInfo->PteInfoList[i].ulNewPteVA = 0;
        }
        if (g_pHookProcessInfo->PteInfoList[i].ulNewPdtVA)
        {
            //释放pdt页面
            MmFreeContiguousMemory((PVOID)g_pHookProcessInfo->PteInfoList[i].ulNewPdtVA);
            g_pHookProcessInfo->PteInfoList[i].ulNewPdtVA = 0;
        }
        if (g_pHookProcessInfo->PteInfoList[i].ulNewPdptVA)
        {
            //释放pdpte页面
            MmFreeContiguousMemory((PVOID)g_pHookProcessInfo->PteInfoList[i].ulNewPdptVA);
            g_pHookProcessInfo->PteInfoList[i].ulNewPdptVA = 0;
        }
    }

    KeLowerIrql(kIrql);         //恢复IRQL
    _enable();                  //开中断
    KeLeaveCriticalRegion();    //开APC

    KeUnstackDetachProcess(&Apc);

    //延时，结束
    LARGE_INTEGER Interval = { 0 };
    Interval.QuadPart = -30ll * 1000ll * 1000ll;//延迟2秒
    KeDelayExecutionThread(KernelMode, FALSE, &Interval);

    //释放跳板
    if (g_pHookProcessInfo->pulTrampoline)
    {
        ExFreePoolWithTag(g_pHookProcessInfo->pulTrampoline, '0etP');
        g_pHookProcessInfo->pulTrampoline = 0;
    }
    //释放Hook结构体
    if (g_pHookProcessInfo)
    {
        ExFreePoolWithTag(g_pHookProcessInfo, 'Info');
        g_pHookProcessInfo = 0;
    }
}