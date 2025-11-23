#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include "logger.h"
#include "HookManager.h"
//定义NtCreateFile函数类型
typedef NTSTATUS(NTAPI* fnNtCreateFile)(
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

//全局函数指针
fnNtCreateFile g_OriNtCreateFile = nullptr;

typedef NTSTATUS(NTAPI* fnMyObpReferenceObjectByHandleWithTag)(HANDLE Handle,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID* Object,
	POBJECT_HANDLE_INFORMATION HandleInformation);

fnMyObpReferenceObjectByHandleWithTag g_OriObpReferenceObjectByHandleWithTag = nullptr;


//编写钩子函数
NTSTATUS
NTAPI
MyNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_ PVOID EaBuffer,
	_In_ ULONG EaLength
) {
	DbgPrintEx(77, 0, "[+]Create file\r\n");
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer
		)
	{
		wchar_t* name = (wchar_t*)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
		if (name) {
			//将文件名复制到新缓冲区
			RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
			RtlCopyMemory(name + (ObjectAttributes->ObjectName->Length / sizeof(wchar_t)), L"\0", sizeof(wchar_t));
			if (wcsstr(name, L"test.txt")) {
				ExFreePool(name);
				return STATUS_ACCESS_DENIED;
			}
			ExFreePool(name);
		}
	}
	return g_OriNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

void DrivrUnload(PDRIVER_OBJECT DriverObject) {
	Dbg("[+]DrivrUnload");
}
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload=DrivrUnload;
	Dbg("[+]DriverEntry" CRLF);
	g_OriNtCreateFile = &NtCreateFile;
	Dbg("[+]Hook NtCreateFile address: %p" CRLF, NtCreateFile);
	auto instance = HookManager::getInstace();
	HANDLE hModule=(HANDLE)3412;
	auto ret = instance->fn_pte_inline_hook(hModule, (void**)&g_OriNtCreateFile, (PVOID*)&MyNtCreateFile);
	return STATUS_SUCCESS;
}
