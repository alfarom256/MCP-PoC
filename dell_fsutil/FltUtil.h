#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <vector>
#include <unordered_map>
#include "../DemoMinifilter/FltDef.h"
#include "PebLdr.h"
#include "MemHandler.h"

// I can hear the OSR replies now... 
#define FLTGLB_OFFSET_FLT_RESOURCE_LISTHEAD 0x58
#define FLT_RESOURCE_LISTHEAD_OFFSET_FRAME_LIST 0x68
#define FLT_RESOURCE_LISTHEAD_OFFSET_FRAME_COUNT 0x78

#define FLT_FRAME_OFFSET_FILTER_RESOUCE_LISTHEAD 0x48
#define FILTER_RESOUCE_LISTHEAD_OFFSET_COUNT 0x78
#define FILTER_RESOUCE_LISTHEAD_OFFSET_FILTER_LISTHEAD 0x68

#define FILTER_OFFSET_NAME 0x38
#define FILTER_OFFSET_OPERATIONS 0x1a8
#define FILTER_OFFSET_INSTANCELIST 0x68

#define FILTER_INSTANCELIST_OFFSET_INSTANCES_COUNT 0x78
#define FILTER_INSTANCELIST_OFFSET_INSTANCES_LIST 0x68

#define FRAME_OFFSET_VOLUME_LIST 0xc8
#define VOLUME_LIST_OFFSET_COUNT 0x78
#define VOLUME_LIST_OFFSET_LIST 0x68

#define VOLUME_OFFSET_DEVICE_NAME 0x60
#define VOLUME_OFFSET_CALLBACK_TBL 0x120

#define CALLBACK_NODE_OFFSET_PREOP 0x18
#define CALLBACK_NODE_OFFSET_POSTOP 0x20

#define UNISTR_OFFSET_LEN 0
#define UNISTR_OFFSET_BUF 8

typedef struct _HANDY_FUNCTIONS {
	PVOID FuncReturns0;
	PVOID FuncReturns1;
}HANDY_FUNCTIONS, *PHANDY_FUNCTIONS;

class FltManager
{
public:
	FltManager(MemHandler* objMemHandler);
	~FltManager();
	PVOID lpFltMgrBase = { 0 };
	PVOID lpFltGlobals = { 0 };
	PVOID lpFltFrameList = { 0 };
	PVOID GetFilterByName(const wchar_t* strFilterName);
	PVOID GetFrameForFilter(LPVOID lpFilter);
	std::vector<FLT_OPERATION_REGISTRATION> GetOperationsForFilter(PVOID lpFilter);
	BOOL ResolveFunctionsForPatch(PHANDY_FUNCTIONS lpHandyFunctions);

	std::unordered_map<wchar_t*, PVOID> EnumFrameVolumes(LPVOID lpFrame);
	DWORD GetFrameCount();
	BOOL RemovePrePostCallbacksForVolumesAndCallbacks(
		std::vector<FLT_OPERATION_REGISTRATION> vecTargetOperations, 
		std::unordered_map<wchar_t*, PVOID> mapTargetVolumes,
		PHANDY_FUNCTIONS lpHandyFuncs
	);

private:
	ULONG ulNumFrames;
	PVOID ResolveDriverBase(const wchar_t* strDriverName);
	PVOID ResolveFltmgrGlobals(LPVOID lpkFltMgrBase);
	PVOID FindRet1(LPVOID lpNtosBase, _ppeb_ldr ldr);
	PVOID FindRet0(LPVOID lpNtosBase, _ppeb_ldr ldr);

	MemHandler* objMemHandler;

};

static std::unordered_map<BYTE, const char*> g_IrpMjMap {
	{0, "IRP_MJ_CREATE"},
	{1, "IRP_MJ_CREATE_NAMED_PIPE"},
	{2, "IRP_MJ_CLOSE"},
	{3, "IRP_MJ_READ"},
	{4, "IRP_MJ_WRITE"},
	{5, "IRP_MJ_QUERY_INFORMATION"},
	{6, "IRP_MJ_SET_INFORMATION"},
	{7, "IRP_MJ_QUERY_EA"},
	{8, "IRP_MJ_SET_EA"},
	{9, "IRP_MJ_FLUSH_BUFFERS"},
	{0xa, "IRP_MJ_QUERY_VOLUME_INFORMATION"},
	{0xb, "IRP_MJ_SET_VOLUME_INFORMATION"},
	{0xc, "IRP_MJ_DIRECTORY_CONTROL"},
	{0xd, "IRP_MJ_FILE_SYSTEM_CONTROL"},
	{0xe, "IRP_MJ_DEVICE_CONTROL"},
	{0xf, "IRP_MJ_INTERNAL_DEVICE_CONTROL"},
	{0x10, "IRP_MJ_SHUTDOWN"},
	{0x11, "IRP_MJ_LOCK_CONTROL"},
	{0x12, "IRP_MJ_CLEANUP"},
	{0x13, "IRP_MJ_CREATE_MAILSLOT"},
	{0x14, "IRP_MJ_QUERY_SECURITY"},
	{0x15, "IRP_MJ_SET_SECURITY"},
	{0x16, "IRP_MJ_POWER"},
	{0x17, "IRP_MJ_SYSTEM_CONTROL"},
	{0x18, "IRP_MJ_DEVICE_CHANGE"},
	{0x19, "IRP_MJ_QUERY_QUOTA"},
	{0x1a, "IRP_MJ_SET_QUOTA"},
	{0x1b, "IRP_MJ_PNP"},
	{0x1b, "IRP_MJ_PNP_POWER"},
	{0x1b, "IRP_MJ_MAXIMUM_FUNCTION"},
	{((UCHAR)-1), "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION"},
	{((UCHAR)-2), "IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION"},
	{((UCHAR)-3), "IRP_MJ_ACQUIRE_FOR_MOD_WRITE"},
	{((UCHAR)-4), "IRP_MJ_RELEASE_FOR_MOD_WRITE"},
	{((UCHAR)-5), "IRP_MJ_ACQUIRE_FOR_CC_FLUSH"},
	{((UCHAR)-6), "IRP_MJ_RELEASE_FOR_CC_FLUSH"},
	{((UCHAR)-7), "IRP_MJ_QUERY_OPEN"},
	{((UCHAR)-13), "IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE"},
	{((UCHAR)-14), "IRP_MJ_NETWORK_QUERY_OPEN"},
	{((UCHAR)-15), "IRP_MJ_MDL_READ"},
	{((UCHAR)-16), "IRP_MJ_MDL_READ_COMPLETE"},
	{((UCHAR)-17), "IRP_MJ_PREPARE_MDL_WRITE"},
	{((UCHAR)-18), "IRP_MJ_MDL_WRITE_COMPLETE"},
	{((UCHAR)-19), "IRP_MJ_VOLUME_MOUNT"},
	{((UCHAR)-20), "IRP_MJ_VOLUME_DISMOUNT"}
};