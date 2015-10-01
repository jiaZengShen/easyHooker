#include "stdafx.h"
#include "mhook/mhook-lib/mhook.h"

//////////////////////////////////////////////////////////////////////////
// Defines and typedefs

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

typedef struct _MY_SYSTEM_PROCESS_INFORMATION 
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;



//typedef VOID GetLocalTime(
//	LPSYSTEMTIME lpSystemTime //address of system times structure
//	);
typedef WINBASEAPI
	VOID
	(WINAPI	*GETLocalTime)(
	__out LPSYSTEMTIME lpSystemTime
	);
GETLocalTime loclTimeFun = (GETLocalTime)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "GetLocalTime");
VOID WINAPI HookedLocalTime(__out LPSYSTEMTIME pTime)
{
	loclTimeFun(pTime);//修改你自己定义的日期
	pTime->wYear=2014;
	pTime->wMonth = 8;
	pTime->wDayOfWeek = 6 ;
	pTime->wDay = 1 ;
	pTime->wHour = 16 ;
	pTime->wMinute = 24 ;
	return ;
}

typedef WINBASEAPI
	VOID
	(WINAPI*	GETSystemTimeAsFileTime)(
	__out LPFILETIME lpSystemTimeAsFileTime
	);
GETSystemTimeAsFileTime fileTimeFun = (GETSystemTimeAsFileTime)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "GetSystemTimeAsFileTime");
VOID WINAPI HookedFileTime(__out LPFILETIME pTime)
{
	fileTimeFun(pTime);
	pTime->dwHighDateTime = 30460982;//2015年8月1日
	pTime->dwLowDateTime = 703426899;
}



//////////////////////////////////////////////////////////////////////////
// Entry point

BOOL WINAPI DllMain(
    __in HINSTANCE  hInstance,
    __in DWORD      Reason,
    __in LPVOID     Reserved
    )
{        
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        //Mhook_SetHook((PVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
		Mhook_SetHook((PVOID*)&loclTimeFun, HookedLocalTime);
		Mhook_SetHook((PVOID*)&fileTimeFun,HookedFileTime);
        break;

    case DLL_PROCESS_DETACH:
        //Mhook_Unhook((PVOID*)&OriginalNtQuerySystemInformation);
		Mhook_Unhook((PVOID*)&loclTimeFun);
		Mhook_Unhook((PVOID*)&fileTimeFun);
        break;
    }

    return TRUE;
}
