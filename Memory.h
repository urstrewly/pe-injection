#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>


class MemoryManager
{
public:
	MemoryManager();
	~MemoryManager();

	int		GetProcessByName(const char* title);
	int		AllocatTarget();

	HANDLE  hProcess;
	int     ProcessId;

private:




};

