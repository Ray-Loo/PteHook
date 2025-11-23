#include "util.h"

//物理地址转线性地址
UINT64 paToVa(UINT64 physicalAddress) {
    PHYSICAL_ADDRESS addr = { 0 };
    addr.QuadPart = physicalAddress;
    return (UINT64)MmGetVirtualForPhysical(addr);
}

//线性地址转物理地址
UINT64 vaToPa(UINT64 virtualAddress) {
    return MmGetPhysicalAddress((void*)virtualAddress).QuadPart;
}

bool MdlWriteMemory(PVOID pBaseAddress, PVOID pWriteData, SIZE_T writeDataSize)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;

	// 创建mdl
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{
		return FALSE;
	}

	// 更新MDL对物理内存的描述
	MmBuildMdlForNonPagedPool(pMdl);
	// 映射到虚拟内存中
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
	}

	// 写入数据
	RtlCopyMemory(pNewAddress, pWriteData, writeDataSize);
	// 释放
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	return true;
}