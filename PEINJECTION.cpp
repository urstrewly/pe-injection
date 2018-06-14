// PEINJECTION.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Memory.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

int main()
{
	MemoryManager mem;

	mem.GetProcessByName("Steam.exe");
	mem.AllocatTarget();
	
	std::cout << "in main: " << mem.hProcess << std::endl;
	std::cout << "int main: " << mem.ProcessId << std::endl;

	CloseHandle(mem.hProcess);
    return 0;
}

