#include "hookmanager.h"
HookManager* HookManager::m_instance;

HookManager* HookManager::getInstace()
{
	//初始化流程
	if (m_instance == nullptr) {
		m_instance = (HookManager*)ExAllocatePoolWithTag(NonPagedPool, sizeof(HookManager), 'hook');//内核分配内存
		m_instance->m_hook_count=0;
		RtlSecureZeroMemory(m_instance->m_hook_info, sizeof(HOOK_INFO) * MAX_HOOK_SIZE);
		RtlSecureZeroMemory(m_instance->m_globalBit, sizeof(UINT32)* MAX_HOOK_SIZE);
		m_instance->m_trampLine = (unsigned char*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'line');
		m_instance->m_trampLineUsed =0;
	}
	return m_instance;
}

bool HookManager::fn_pte_inline_hook(HANDLE pid, void** oFuncAddr, void* targetFuncAddr)
{
	PEPROCESS Process{ 0 };
	KAPC_STATE Apc{ 0 };
	NTSTATUS status;
	const uint32_t breakBytesLeast = 14;//ff 25
	const uint32_t trampLineBreakBytes = 20;
	uint32_t uBreakBytes = 0;
	unsigned char* TrampLine = m_trampLine + m_trampLineUsed;
	hde64s hde_info{ 0 };
	char* JmpAddrStart = (char*)*oFuncAddr;//获取原函数地址
	Dbg("[!]original function addr:%p\r\n", *oFuncAddr);
	if (m_hook_count >= MAX_HOOK_SIZE) {
		Dbgf("[-]Hook too much.\r\n");
		return false;
	}
	status = PsLookupProcessByProcessId(pid, &Process);
	if (!NT_SUCCESS(status)) {
		Dbgf("[-]failed to get pid.\r\n");
		return false;
	}
	//隔离原函数地址
	auto ret = fn_isolation_pages(pid, *oFuncAddr);
	if (!ret)return false;
	Dbg("[+]isolation susccess.\r\n");
	while (uBreakBytes < breakBytesLeast) {
		if (!hde64_disasm(JmpAddrStart + uBreakBytes, &hde_info)) {
			Dbgf("[-]failed to diasm addr.\r\n");
			ObDereferenceObject(Process);
			return false;
		}
		uBreakBytes += hde_info.len;
	}
	Dbg( "[+]fn_pte_inline_hook:finish disasm.\r\n");
	unsigned char trampLineCode[trampLineBreakBytes] = {
		0x6A, 0x00,                                                // push 0
		0x3E, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,            // mov dword ptr ss : [rsp] , 0x00
		0x3E, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,      // mov dword ptr ss : [rsp + 4] , 0x00
		0xC3                                                       // ret
	};
	char absolutejmpCode[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	*((PUINT32)&trampLineCode[6]) = (UINT32)(((uint64_t)JmpAddrStart + uBreakBytes) & 0XFFFFFFFF);
	*((PUINT32)&trampLineCode[15]) = (UINT32)((((uint64_t)JmpAddrStart + uBreakBytes) >> 32) & 0XFFFFFFFF);

	RtlCopyMemory(TrampLine, JmpAddrStart, uBreakBytes);
	RtlCopyMemory(TrampLine + uBreakBytes, trampLineCode, sizeof(trampLineCode));
	//添加Hook信息
	for (int i = 0; i < MAX_HOOK_SIZE; i++) {
		if (m_hook_info[i].pid == 0) {
			m_hook_info[i].original_func_ptr = JmpAddrStart;
			RtlCopyMemory(m_hook_info[i].original_bytes, JmpAddrStart, uBreakBytes);
			m_hook_info[i].pid = pid;
			m_hook_count++;
			break;
		}
	}
	Dbg("[+]ready to create trampline.\r\n");
	*((ULONG64*)(&absolutejmpCode[6])) = (ULONG64)targetFuncAddr;
	Dbg("[!]fn_pte_inline_hook:KeStackAttachProcess!\r\n");
	KeStackAttachProcess(Process, &Apc);
	
	Dbg("[+][absolutejmpCode]\r\n");
	for (int i = 0; i < 14; i++) {
		Dbg("%02X", (unsigned char)absolutejmpCode[i]);
	}
	Dbg(CRLF);
	/*BOOLEAN success = MdlWriteMemory(JmpAddrStart, absolutejmpCode, 14);
	if (!success) {
		Dbgf("[-]failed to MDL write jmpcode.\r\n");
		return false;
	}*/
	Dbg("[!]fn_pte_inline_hook:fn_pte_wp_disable!\r\n");
	KIRQL old_irql = fn_pte_wp_disable();
	RtlCopyMemory(JmpAddrStart, absolutejmpCode, 14);
	Dbg("[!]fn_pte_inline_hook:fn_pte_wp_enable!\r\n");
	fn_pte_wp_enable(old_irql);
	Dbg("[!]fn_pte_inline_hook:KeUnstackDetachProcess!\r\n");
	KeUnstackDetachProcess(&Apc);
	*oFuncAddr = TrampLine;
	m_trampLineUsed += uBreakBytes + trampLineBreakBytes;
	ObDereferenceObject(Process);
	return true;
}

bool HookManager::fn_pte_inline_unhook(HANDLE process_id, void* hk_addr)
{
	//wait to fix
	return false;
}

void HookManager::fn_pte_add_g_bit_info(void* align_addr, PDE* pde_addr, PTE* pte_addr)
{
	//wait to fix
}

void HookManager::fn_resume_global_bit(void* align_addr) 
{
	//wait to fix
}

KIRQL HookManager::fn_pte_wp_disable()
{
	//关闭CR0
	//KeRaiseIrqlToDpcLevel 是 Windows 内核模式下用于提升 IRQL 的函数。
	//较高的 IRQL 级别会屏蔽较低级别的中断，确保在高优先级任务执行期间不会被低优先级中断打断。
	auto irql = KeRaiseIrqlToDpcLevel();//关闭线程切换，因为提升了irql
	UINT64 CR0 = __readcr0();
	CR0 &= 0xfffffffffffeffff;//改变第16位
	__writecr0(CR0);
	_disable();//关闭中断
	return irql;//返回原IRQL，用于恢复
}

void HookManager::fn_pte_wp_enable(KIRQL old_irql)
{
	UINT64 CR0 = __readcr0();
	CR0 |= 0x10000;
	_enable();//开启中断
	__writecr0(CR0);//恢复CR0
	KeLowerIrql(old_irql);//恢复原IRQL
}



bool HookManager::fn_isolation_pages(HANDLE process_handle, void* iso_virtual_address)
{
	NTSTATUS status = STATUS_SUCCESS;
	//用于KeStackAttachProcess，需要正确进程对象
	PEPROCESS Process;
	KAPC_STATE Apc{ 0 };

	//获取目标进程
	if (process_handle != (HANDLE)4) {
		status = PsLookupProcessByProcessId(process_handle, &Process);
		if (!NT_SUCCESS(status)) {
			Dbgf("[-]fn_isolation_pages:failed to get EPROCESS.\r\n");
			return false;
		}
	}
	else {
		Process=PsGetCurrentProcess();
	}


	//附加获取正确CR3和页表
	Dbg("[!]fn_isolation_pages:KeStackAttachProcess\r\n");
	KeStackAttachProcess(Process, &Apc);

	CR3 cr3 = { __readcr3() };
	//获取pagetable
	PAGE_TABLE pagetable = { 0 };
	//按4kb向下对齐到位置
	pagetable.LineAddress = (UINT64)(PAGE_ALIGN(iso_virtual_address));
	//获取该地址对齐后的页表，这里是默认获取正确
	page_table::GetPageTable(&pagetable);

	bool bSuc = false;
	while (1) {
		PDE splid_pde = { 0 };
		//大页
		if (pagetable.pdeAddress->Fields2MB.PS) {//这一行有问题
			Dbg("[+]fn_isolation_pages:fn_split_pages!\r\n");
			bSuc = fn_split_pages(pagetable.pdeAddress, &splid_pde);
			if (!bSuc) {
				//分割失败
				Dbgf("[-]fn_split_pages failed!\r\n");
				break;
			}
			//目前不能更改G位，只有替换了才能脱钩，未验证
		}
		__try {//隔离页表
			bSuc = fn_isolation_pagetable((void*)pagetable.LineAddress, &splid_pde);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Dbgf("[-]Exception during page isolation : 0x%X" CRLF, GetExceptionCode());
			bSuc = false;
			break;
		}
		break;
	}
	Dbg("[!]fn_isolation_pages:KeUnstackDetachProcess!\r\n");
	KeUnstackDetachProcess(&Apc);
	if (process_handle != (HANDLE)4)//作用未知，不清楚为什么hook system进程不需要ObDereferenceObject
		ObDereferenceObject(Process);
	if (!bSuc) {
		Dbgf("[-]fn_isolation_pages:failed!!\r\n");
	}
	return bSuc;
}


bool HookManager::fn_isolation_pagetable(void* replace_align_addr, PDE* split_pde)
{
	PAGE_TABLE pagetable = { 0 };
	void* fake_page_start = nullptr;
	PDPTE* pdpte_ptr;
	PDE* pde_ptr;
	PTE* pte_ptr;
	unsigned char* fake_4kb_memory;

	INT64 pml4e_index, pdpte_index, pde_index, pte_index;
	UINT64 addr = (UINT64)replace_align_addr & 0x0000ffffffffffff;
	//提取索引
	pml4e_index = (addr & 0xff8000000000) >> 38;//提取39-47位
	pdpte_index = (addr & 0x007fc0000000) >> 30;//提取30-38位
	pde_index = (addr & 0x00003fe00000) >> 21;//提取21-29位
	pte_index = (addr & 0x0000001ff000) >> 12;//提取12-20位
	Dbg("[+]fn_isolation_pagetable:pml4e_index=%llx,pdpte_index=%llx,pde_index=%llx,pte_index=%llx\r\n", pml4e_index, pdpte_index, pde_index, pte_index);
	
	//分配连续的内存
	//小页分配4Kb,如果是大页只用分配3个页,12KB内存
	int pageNums = NULL;
	if (split_pde->value!=0) {
		pageNums = 3;
	}
	else {
		pageNums = 4;
	}
	Dbg("[+]fn_isolation_pagetable:allocating %d pages.\r\n", pageNums);
	//注意，这个函数IRQL<= DISPATCH_LEVEL
	PHYSICAL_ADDRESS low = { 0 }, high = { 0 };
	high.QuadPart = MAXULONG64;
	//对齐属性
	LARGE_INTEGER alignment = { 0 };
	fake_page_start = MmAllocateContiguousMemorySpecifyCache(
		pageNums * PAGE_SIZE,//4*4KB‘

		low,//调用方可以使用的最低有效物理地址
		high,//调用方可以使用的最高有效物理地址
		alignment,
		MmCached);
	if (fake_page_start == nullptr) {
		//申请失败
		Dbgf("[-]fn_isolation_pagetable:MmAllocateContiguousMemorySpecifyCache failed!\r\n");
		return false;
	}
	Dbg("[+]fn_isolation_pagetable:MmAllocateMemore success at %p!!!\r\n", fake_page_start);

	pagetable.LineAddress = (UINT64)PAGE_ALIGN(replace_align_addr);
	page_table::GetPageTable(&pagetable);//目前还是KeStackAttachProcess后能够获取的正确页表

	// ============== 正确处理大页分割后的情况 ==============
	//接下来的指针都要是虚拟地址
	//申请内存的第一页头部地址是伪造的PDPTE
	pdpte_ptr = (PDPTE*)fake_page_start;
	if (pageNums == 4) {//小页
		pde_ptr = (PDE*)((UINT64)fake_page_start + PAGE_SIZE);
		pte_ptr = (PTE*)((UINT64)fake_page_start + PAGE_SIZE * 2);
		fake_4kb_memory = (unsigned char*)((UINT64)fake_page_start + PAGE_SIZE * 3);
		//小页PTE有值,从头部直接复制全部内容
		UINT64 pt_va = (UINT64)pagetable.pteAddress - pte_index * 8;//头部
		Dbg("[!]fn_isolation_pagetable:RtlCopyMemory!\r\n");
		RtlCopyMemory(pte_ptr, (void*)pt_va, PAGE_SIZE);
	}
	else {//大页使用分割后的PDE
		//split的输出pde
		pde_ptr = (PDE*)((UINT64)fake_page_start + PAGE_SIZE);
		//大页PTE没有值,使用分割后的PDE，分割后已有值
		UINT64 pte_pa = split_pde->Fields4K.PPN << 12;
		pte_ptr = (PTE*)paToVa(pte_pa);//获取pte头部虚拟地址
		fake_4kb_memory = (unsigned char*)((UINT64)fake_page_start + PAGE_SIZE * 2);//第三页
	}
	// ============== 修复结束 ==============
	//关闭中断，防止写入假页表时发生异常
	_disable();
	//复制页表
	//关键在于我们要复制的页表要去掉索引,拿到页表头,然后每个页表的4Kb完整复制
	if (!MmIsAddressValid((void*)pagetable.LineAddress)) {
		Dbgf("[-]fn_isolation_pagetable:LineAddress addr not valid!\r\n");
	}
	Dbg("[!]fn_isolation_pagetable:RtlCopyMemory!\r\n");
	RtlCopyMemory(fake_4kb_memory, (void*)pagetable.LineAddress, PAGE_SIZE);

	if (!MmIsAddressValid((void*)((UINT64)pagetable.pdeAddress - pde_index * 8))) {
		Dbgf("[-]fn_isolation_pagetable:pdeAddress addr not valid!\r\n");
	}
	Dbg("[!]fn_isolation_pagetable:RtlCopyMemory!\r\n");
	RtlCopyMemory(pde_ptr, (void*)((UINT64)pagetable.pdeAddress - pde_index * 8), PAGE_SIZE);
	if (!MmIsAddressValid((void*)((UINT64)pagetable.pdpteAddress - pdpte_index * 8))) {
		Dbgf("[-]fn_isolation_pagetable:pdpteAddress addr not valid!\r\n");
	}
	Dbg("[!]fn_isolation_pagetable:RtlCopyMemory!\r\n");
	RtlCopyMemory(pdpte_ptr, (void*)((UINT64)pagetable.pdpteAddress - pdpte_index * 8), PAGE_SIZE);
	//修改页表，关键理解物理页号和物理地址之间的关系，需要去除低12位得到物理页号
	Dbg("[!]fn_isolation_pagetable:alter pte_ptr[pte_index] pde_ptr[pde_index] pdpte_ptr[pdpte_index] PPN");
	//这里出现了错误，说明还是只能通过位修改
	pte_ptr[pte_index].Fields4K.PPN = vaToPa((UINT64)fake_page_start) / PAGE_SIZE;//替换假pte中的指定物理页
	pde_ptr[pde_index].Fields4K.PPN = vaToPa((UINT64)pte_ptr) / PAGE_SIZE;//替换假pde中的指定pte
	pdpte_ptr[pdpte_index].Fields4K.PPN = vaToPa((UINT64)pde_ptr) / PAGE_SIZE;//替换假pdpte中的指定pde
	pte_ptr[pte_index].Fields4K.G = 0;//清除全局位
	//恢复中断
	_enable();
	CR3 cr3 = { __readcr3() };
	//----------关键访问和修改操作，必须这样才能修改页表值
	//	替换真页表项
	UINT64 *pmladdr = (UINT64*)paToVa(cr3.Fields.PPN << 12);//获取pml4e的可修改虚拟地址
	//pmladdr[pml4e_index].Fields4K.PPN = vaToPa((UINT64)pdpte_ptr) / PAGE_SIZE;//这一项出错了，只能添加位的方式写入，而且这里不能有线程切换等东西，也要处于高IRQL!!
	UINT64 pml_pa = cr3.Fields.PPN;//获0取物理地址
	DbgBreakPoint();
	UINT64 *pml_tmp = &pmladdr[pml4e_index];//使指针的值正确的指向地址
	KIRQL old_irql = fn_pte_wp_disable();
	*pml_tmp &= 0x000FFFFFFFFFF000;//清除地址位
	*pml_tmp |= pml_pa;//添加物理地址
	Dbg("[!]fn_isolation_pagetable:fn_pte_wp_disable!!!" CRLF);
	//----------结束
	fn_pte_wp_enable(old_irql);
	Dbg("[!]fn_isolation_pagetable:fn_pte_wp_enable!!!" CRLF);
	//刷新指定地址的TLB
	__invlpg((void*)pmladdr);
	return true;
}

//把某个大页PDE指向小页PTE,我们替换的是该PDE指向的4kb小页PT表
bool HookManager::fn_split_pages(PDE* in_pde, PDE* out_pde)
{
	//构造的需要遍历PDE的指针，分配4kb内存存放小页并遍历pt
	//分配512*8字节=4kb内存
	PHYSICAL_ADDRESS low = { 0 }, high = { 0 };
	LARGE_INTEGER alignment = { 0 };
	PTE* pt = (PTE*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high, alignment, MmCached);
	if (!pt) {
		Dbgf("[-]MmAllocateContiguousMemorySpecifyCache failed!\r\n");
		return false;
	}
	RtlZeroMemory(pt, PAGE_SIZE);

	//构造512个PTE，每个PTE指向一个4kb小页
	UINT64 start_ppn = in_pde->Fields2MB.PPN; // 计算原始 2MB 区域的物理起始地址
	for (int i = 0; i < 512; i++) {
		pt[i].value = in_pde->value;
		pt[i].Fields4K.G = 0;
		pt[i].Fields4K.PPN= start_ppn+i;//可以想象我们第二项管理的是第二个4Kb内存位置，然而我们Pte是不是还要加上12位，刚好就是第二个4Kb的开头
	}

	//复制原PDE的内容到新PDE
	//out_pde->flags=in_pde->flags;
	out_pde->value = in_pde->value;
	out_pde->Fields4K.PS = 0;
	out_pde->Fields4K.PPN = vaToPa((UINT64)pt)/PAGE_SIZE;
	Dbg("[+]Split large page:PFN=0x%llx -> new PT at 0x%p" CRLF, start_ppn, pt);
	return true;
}

