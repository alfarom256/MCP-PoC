#include "memory.h"

Memory::Memory() {
	/* Constructor for Memory Manager */
	// Opens a handle to dbutil_2_3
	Memory::DriverHandle = CreateFileW(L"\\\\.\\dbutil_2_3", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	// Checks if handle was opened succesfully
	if (Memory::DriverHandle == INVALID_HANDLE_VALUE) {
		printf("Failed to open handle to device\t0x%x\n", GetLastError());
		exit(1);
	}
	puts("Connected to device");
}

BOOL Memory::VirtualRead(_In_ DWORD64 address, _Out_ void *buffer, _In_ size_t bytesToRead) {
	/* Reads VIRTUAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, 0x8);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, 0x8);
	// Copies the offset value to the third 8 bytes (offset bytes, added to address inside driver)
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, 0x8);
	// Sends the IOCTL_READ code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(Memory::DriverHandle, IOCTL_VIRTUAL_READ, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Copies the returned value to the output buffer
	memcpy(buffer, &tempBuffer[0x18], bytesToRead);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL Memory::VirtualWrite(_In_ DWORD64 address, _In_ void *buffer, _In_ size_t bytesToWrite) {
	/* Reads VIRTUAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Copies the offset value to the third 8 bytes (offset bytes, added to address inside driver)
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, PARAMETER_SIZE);
	// Copies the write data to the end of the header
	memcpy(&tempBuffer[0x18], buffer, bytesToWrite);
	// Sends the IOCTL_WRITE code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(Memory::DriverHandle, IOCTL_VIRTUAL_WRITE, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL Memory::PhysicalRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead) {
	/* Reads PHYSICAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = PHYSICAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Sends the IOCTL_READ code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(Memory::DriverHandle, IOCTL_PHYSICAL_READ, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Copies the returned value to the output buffer
	memcpy(buffer, &tempBuffer[0x10], bytesToRead);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL Memory::PhysicalWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite) {
	/* Reads PHYSICAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = PHYSICAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Copies the write data to the end of the header
	memcpy(&tempBuffer[0x10], buffer, bytesToWrite);
	// Sends the IOCTL_WRITE code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(Memory::DriverHandle, IOCTL_PHYSICAL_WRITE, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}
