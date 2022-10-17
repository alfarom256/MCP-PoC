#include <fltKernel.h>
#include <ntddk.h>

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDrvObj, _In_ PUNICODE_STRING pRegPath);
NTSTATUS FsFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

PFLT_FILTER g_FilterHandle;
static const UNICODE_STRING g_TargetFileName = RTL_CONSTANT_STRING(L"\\Users\\User\\Desktop\\test.txt");


FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
	_Inout_ PFLT_CALLBACK_DATA lpFltCallbackData,
	_In_ PCFLT_RELATED_OBJECTS lpFltRelatedObj, 
	_Out_ PVOID* lpCompletionContext)
{

	UNREFERENCED_PARAMETER(lpFltCallbackData);
	*lpCompletionContext = NULL;
	PFILE_OBJECT lpFileObject = lpFltRelatedObj->FileObject;
	PUNICODE_STRING lpFileName = &lpFileObject->FileName;

	// desktop\test.txt
	if (RtlCompareUnicodeString(&g_TargetFileName, lpFileName, TRUE) == 0) {
		HANDLE hPid = PsGetCurrentProcessId();
		DbgPrint("[DEMOFLT] PID %p - Create - %wZ\n", hPid, lpFileName);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


const FLT_OPERATION_REGISTRATION Callbacks[] = {
	{
		IRP_MJ_CREATE,
		0,
		PreCreateCallback,
		NULL,
	},
	{ IRP_MJ_OPERATION_END }
};

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_registration
const FLT_REGISTRATION FltRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	NULL,
	Callbacks,
	FsFilterUnload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

NTSTATUS FsFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);
	FltUnregisterFilter(g_FilterHandle);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDrvObj, _In_ PUNICODE_STRING pRegPath) {
	UNREFERENCED_PARAMETER(pDrvObj);
	UNREFERENCED_PARAMETER(pRegPath);
	NTSTATUS status = 0;

	status = FltRegisterFilter(pDrvObj, &FltRegistration, &g_FilterHandle);
	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(g_FilterHandle);
		return status;
	}

	FltStartFiltering(g_FilterHandle);
	return status;
}