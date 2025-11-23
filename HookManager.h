#pragma once
//#include <ntddk.h>
//#include <wdm.h>
//#include <ntifs.h>
// 首先包含 Windows 基本头文件
#include <ntdef.h>
#include <ntifs.h>
#include <wdm.h>
// 然后包含 NT 头文件
#include <ntddk.h>
#include ".\IA32E\x64Common.h"
#include ".\IA32E\pagetable.h"
#include "util.h"
#include ".\hde\hde64.h"

#define MAX_HOOK_SIZE 0x100


//恢复结构，保存原函数地址和原函数的字节数组	
typedef struct _inline_hook_record {
    HANDLE pid;
    void* original_func_ptr;
    unsigned char* original_bytes[14];//FF 25 ?? ??

}HOOK_INFO, * PHOOK_INFO;

class HookManager {
public:
    static HookManager* getInstace();
    //Pte Inline hook
    bool fn_pte_inline_hook(HANDLE pid, void** oFuncAddr, void* targetFuncAddr);
    //移除钩子
    bool fn_pte_inline_unhook(HANDLE process_id, void* hk_addr);

private:
    //添加G位信息方便恢复
    void fn_pte_add_g_bit_info(void* align_addr, PDE* pde_addr, PTE* pte_addr);
    void fn_resume_global_bit(void* align_addr);
    //开启关闭CR0的WP位，注意一定要在写入的时候再开启，否则PG检查很快！！！
    KIRQL fn_pte_wp_disable();
    void fn_pte_wp_enable(KIRQL old_irql);
    //隔离指定进程虚拟地址所在的页
    //这里需要兼容大页
    bool fn_isolation_pages(HANDLE process_handle, void* iso_virtual_address);
    
    //隔离页表结构
    bool fn_isolation_pagetable(void* replace_align_addr, PDE* split_pde);
    //2Mb PDE拆分
    bool fn_split_pages(PDE* in_pde, PDE* out_pde);


private:
    //单例
    static HookManager* m_instance;

    void* m_PTEBase;
    HOOK_INFO m_hook_info[MAX_HOOK_SIZE];
    UINT32 m_globalBit[MAX_HOOK_SIZE];
    

    UINT32 m_hook_count;

    //蹦床
    unsigned char* m_trampLine;
    //蹦床使用字节数
    UINT64 m_trampLineUsed;
};