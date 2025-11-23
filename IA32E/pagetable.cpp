#include "pagetable.h"
#include "..\logger.h"
PTE* page_table::GetPteBase4KB()
{
	CR3 cr3 = { __readcr3() };//获取cr3，可以从ppn取出物理地址
	PML4E* cr3va = { 0 };//要得到cr3的虚拟地址
	cr3va = (PML4E*)paToVa(cr3.Fields.PPN << 0xC);//还原物理地址后，转换成虚拟地址
	if (!MmIsAddressValid((PVOID)cr3va)) {
		Dbg("cr3va is not valid\r\n");
		return NULL; // 如果转换失败，返回 NULL
	}
	//遍历这个PML4E表中，根据页表自映射原理，找到PTE的起始地址
	for (UINT64 i = 0; i < 512; ++i) {
		if (cr3va[i].Fields4K.PPN == cr3.Fields.PPN) {//页表自映射原理，这里主要是找和cr3值一样的项，得到他的索引
			return (PTE*)((0xffff000000000000) | (i << 39));//返回这个地址，并且把它构造成内核地址，为什么是i<<39：因为页表自映射原理，PTE的起始地址是cr3的第一级页表中找到和他一样的项，然后这个索引左移39位+高位扩展就是PTEbase
		}
	}
	return NULL;
}
//把下级页表虚拟地址传进去，然后获取上一级页表的物理地址，可重用函数
UINT64 page_table::getPteBase_by_va(UINT64 virtualAddress) {
	//清除高地址扩展
	virtualAddress &= 0x0000FFFFFFFFFFFF;

	//这里使用auto将会出错
	//获取偏移
	UINT64 offset = (virtualAddress >> 12) << 3;
	//这里面会将高地址扩展加入
	UINT64 pteBase = (UINT64)GetPteBase4KB();//获取PTE的起始地址
	//返回完整的含有高地址扩展的物理地址
	return pteBase + offset;
}

void page_table::GetPageTable(PAGE_TABLE* pageTable) {
    //获取线性地址，我们要获取索引然后加上每个表的基址，然后通过偏移获取他到底在哪一页
    VA virtualAddress = { pageTable->LineAddress };
    //获取各页表基址
	//这里可以优化至只读一次CR3
    pageTable->pteAddress = (PTE*)getPteBase_by_va((UINT64)virtualAddress.value);
    pageTable->pdeAddress = (PDE*)getPteBase_by_va((UINT64)pageTable->pteAddress);
    pageTable->pdpteAddress = (PDPTE*)getPteBase_by_va((UINT64)pageTable->pdeAddress);
    pageTable->pml4eAddress = (PML4E*)getPteBase_by_va((UINT64)pageTable->pdpteAddress);
	CR3 cr3 = { __readcr3() };//获取cr3，可以从ppn取出物理地址
	Dbg("cr3: %p\r\n", cr3.value);
	Dbg("LineAddress: %p\r\n", pageTable->LineAddress);
	Dbg("pml4eAddress: %p\r\n", pageTable->pml4eAddress);
	Dbg("pdpteAddress: %p\r\n", pageTable->pdpteAddress);
	Dbg("pdeAddress: %p\r\n", pageTable->pdeAddress);
	Dbg("pteAddress: %p\r\n", pageTable->pteAddress);
}
