#pragma once
#include <Windows.h>
#include <string>
#include "MemHandler.h"

// IOCTRL Codes for dbutil Driver Dispatch Methods
#define IOCTL_VIRTUAL_READ			0x9B0C1EC4
#define IOCTL_VIRTUAL_WRITE			0x9B0C1EC8
#define IOCTL_PHYSICAL_READ			0x9B0C1F40
#define IOCTL_PHYSICAL_WRITE		0x9B0C1F44

// Size of the parameters/header of each IOCTRL packet/buffer
#define VIRTUAL_PACKET_HEADER_SIZE	0x18
#define PHYSICAL_PACKET_HEADER_SIZE	0x10
#define PARAMETER_SIZE				0x8
#define GARBAGE_VALUE				0xDEADBEEF


class Memory : public MemHandler {
public:
	HANDLE DriverHandle;

	Memory();

	// Virtual Kernel Memory Read Primitive
	BOOL VirtualRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead);

	// Virtual Kernel Memory Write Primitive
	BOOL VirtualWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite);

	// Physical Memory Read Primitive
	BOOL PhysicalRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead);

	// Physical Memory Write Primitive
	BOOL PhysicalWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite);

};