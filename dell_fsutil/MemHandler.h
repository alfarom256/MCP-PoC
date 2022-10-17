#pragma once
#include <Windows.h>
class MemHandler
{
public:
	virtual BOOL VirtualRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead) = 0;
	virtual BOOL VirtualWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite) = 0;
};

