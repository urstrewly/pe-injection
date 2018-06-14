#include "stdafx.h"
#include "Memory.h"
#include <Windows.h>
#include <stdio.h>

DWORD WINAPI ThreadProc(PVOID p)
{
	MessageBox(NULL, "Message from injected code!", "Message", MB_ICONINFORMATION);
	return 0;
}



MemoryManager::MemoryManager()
{
}

MemoryManager::~MemoryManager()
{
	CloseHandle(hProcess);
}

int MemoryManager::GetProcessByName(const char * title)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (snapshot == INVALID_HANDLE_VALUE)
		return -1;

	
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (strcmp(entry.szExeFile, title) == 0) 
			{
				std::cout << "FILE FOUND\t";
				std::cout << entry.szExeFile << "\t\t\t" << title << std::endl;
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, entry.th32ProcessID);
				ProcessId = entry.th32ProcessID;

				return 0;
			}
			else {
				std::cout << "FILE NOT FOUND\t";
				std::cout << entry.szExeFile << "\t\t\t" << title << std::endl;
			}
		}
	}
	else 
	{
		CloseHandle(snapshot);
		return -1;
	}


	return 0;
}

int MemoryManager::AllocatTarget()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	tp.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL, _T("SeDebugPrivilege"), &tp.Privileges[0].Luid);
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);

	AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL);
	CloseHandle(hToken);

	if (!hProcess)
		return -1;

	PVOID CurrentImage = GetModuleHandle(NULL);
	std::cout << "Current process handle: " << CurrentImage << std::endl;

	PIMAGE_DOS_HEADER		Process_IMAGE_DOS_HEADER;
	PIMAGE_NT_HEADERS		PEFileHeader;
	PIMAGE_BASE_RELOCATION  ProcessBReloc;


	Process_IMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)CurrentImage;

	if (!Process_IMAGE_DOS_HEADER) {
		std::cout << "Cannot get IMAGE_DOS_HEADER of current process" << std::endl;
		CloseHandle(hProcess);
		return -1;
	}

	PEFileHeader = (PIMAGE_NT_HEADERS)((PUCHAR)CurrentImage + Process_IMAGE_DOS_HEADER->e_lfanew);


	if (!PEFileHeader)
	{
		std::cout << "Cannot get IMAGE_NT_HEADERS of current process" << std::endl;
		CloseHandle(hProcess);
		return -1;
	}

	PVOID TargetAllocated = VirtualAllocEx(hProcess, NULL, PEFileHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// make dupliation of pe in virtual memory 
	PVOID Buffer  = VirtualAlloc(NULL, PEFileHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


	if (TargetAllocated && Buffer == NULL)
	{
		std::cout << "Cannot allocate memory in target" << std::endl;
		CloseHandle(hProcess);
		return -1;
	}

	std::cout << "Allocated memory inside of target module @: " << TargetAllocated << std::endl;

	// fill in empty buffer with current image
	memcpy(Buffer, CurrentImage, PEFileHeader->OptionalHeader.SizeOfImage);

	ProcessBReloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)Buffer + PEFileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);


	if (!ProcessBReloc)
	{
		std::cout << "Cannot get current image base relocation" << std::endl;
		CloseHandle(hProcess);
		return -1;
	}

	ULONG64 Delta = (ULONG64)TargetAllocated - (ULONG64)CurrentImage;


	if (!Delta)
	{
		std::cout << "Cannot calculate allocated image size" << std::endl;
		CloseHandle(hProcess);
		return -1;
	}


	while (ProcessBReloc->VirtualAddress)
	{
		if (ProcessBReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{

			ULONG64 Count = (ProcessBReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			PUSHORT TypeOffset = (PUSHORT)(ProcessBReloc + 1);

			for (ULONG64 i = 0; i < Count; i++)
			{
				if (TypeOffset[i])
				{
					ULONG64 *p; 
					p = (PULONG64)((PUCHAR)Buffer + ProcessBReloc->VirtualAddress + (TypeOffset[i] & 0xFFF));
					*p += Delta;

				}
			}

		}

		ProcessBReloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)ProcessBReloc + ProcessBReloc->SizeOfBlock);

	}

	// writing executable into target

	if (!WriteProcessMemory(hProcess, TargetAllocated, Buffer, PEFileHeader->OptionalHeader.SizeOfImage, NULL))
	{
		std::cout << "Unable to write executable image into target process" << std::endl;
		CloseHandle(hProcess);
		return -1;
	}
	else {
		std::cout << "Target Process now obtains external executable image" << std::endl;

		VirtualFree(Buffer, 0, MEM_RELEASE);

		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PUCHAR)ThreadProc + Delta), NULL, 0, NULL);

		if (!hThread)
		{
			std::cout << "Unable to create remote thread" << GetLastError() << std::endl;
			VirtualFreeEx(hProcess, TargetAllocated, 0, MEM_RELEASE);

			return -1;
		}


		WaitForSingleObject(hThread, INFINITE);

		VirtualFreeEx(hProcess, TargetAllocated, 0, MEM_RELEASE);
		CloseHandle(hProcess);
	}

	

	return 0;
}

