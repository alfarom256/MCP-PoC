#pragma once
#define ASSERT_SZ( x, y ) static_assert(sizeof(x) == y, "incorrect size for " #x);

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
// begin usermode defs
#include <Windows.h>
#include <winternl.h>

#define IRP_MJ_OPERATION_END 0x80

typedef struct _OWNER_ENTRY {
	DWORD64 OwnerThread;
	DWORD64 TableSize;
}OWNER_ENTRY, *POWNER_ENTRY;

typedef struct _ERESOURCE {
	LIST_ENTRY SystemResourcesList;
	PVOID OwnerTable;
	SHORT ActiveCount;
	WORD Flag;
	PVOID SharedWaiters;
	PVOID ExclWaiters;
	OWNER_ENTRY OwnerEntry;
	ULONG ActiveEntries;
	ULONG ContentionCount;
	ULONG NumberOfSharedWaiters;
	ULONG NumberOfExclusiveWaiters;
	PVOID Reserved2;
	DWORD64 Cbti;
	DWORD64 SpinLock;
}ERESOURCE, *PERESOURCE;
ASSERT_SZ(ERESOURCE , 0x68)

typedef struct _FAST_MUTEX {
	ULONG Count;
	PVOID Owner;
	ULONG Contention;
	PVOID Event[3];
	ULONG OldIrql;
} FAST_MUTEX, * PFAST_MUTEX;
ASSERT_SZ(FAST_MUTEX, 0x38)

typedef struct _KTIMER {
	PVOID Header[3];
	LARGE_INTEGER DueTime;
	LIST_ENTRY TimerListEntry;
	PVOID Kdpc;
	ULONG Processor;
	ULONG Period;
} KTIMER, *PKTIMER;
ASSERT_SZ(KTIMER, 0x40)

typedef struct _KDPC {
	ULONG TargetInfoAsUlong;
	SINGLE_LIST_ENTRY DpcListEntry;
	PVOID ProcessorHistory;
	PVOID DeferredRoutine;
	PVOID DeferredContext;
	PVOID SystemArg1;
	PVOID SystemArg2;
	PVOID DpcData;
}KDPC, *PKDPC;
ASSERT_SZ(KDPC, 0x40)

typedef struct _WORK_QUEUE_ITEM {
	LIST_ENTRY List;
	PVOID WorkerRoutine;
	PVOID Parameter;
}WORK_QUEUE_ITEM, *PWORK_QUEUE_ITEM;
ASSERT_SZ(WORK_QUEUE_ITEM, 0x20)

typedef struct _NPAGED_LOOKASIDE_LIST {
	PVOID ThisTypedefHasBeenLeftAsAnExerciseToTheReader[12];
} NPAGED_LOOKASIDE_LIST, *PNPAGED_LOOKASIDE_LIST;
ASSERT_SZ(NPAGED_LOOKASIDE_LIST, 0x60)

typedef struct _FLT_OPERATION_REGISTRATION {
	UCHAR MajorFunction;
	ULONG Flags;
	PVOID PreOperation;
	PVOID PostOperation;
	PVOID Reserved1;
}FLT_OPERATION_REGISTRATION, *PFLT_OPERATION_REGISTRATION;
ASSERT_SZ(FLT_OPERATION_REGISTRATION, 0x20)

typedef PVOID PKRESOURCEMANAGER;
typedef PVOID PDRIVER_OBJECT;
typedef PVOID PEX_RUNDOWN_REF_CACHE_AWARE;
typedef DWORD64 EX_PUSH_LOCK;
typedef DWORD64 EX_RUNDOWN_REF;
#endif

// end usermode defs

#define OFFSET_FLT_INSTANCE_LIST_ENTRY 0x70
#define CONTEXT_LIST_MAX 50

typedef struct _FLT_RESOURCE_LIST_HEAD {
	ERESOURCE rLock;
	LIST_ENTRY rList;
	ULONG rCount;
} FLT_RESOURCE_LIST_HEAD, *PFLT_RESOURCE_LIST_HEAD;
ASSERT_SZ(FLT_RESOURCE_LIST_HEAD, 0x80)

typedef struct _FLT_MUTEX_LIST_HEAD {
	FAST_MUTEX mLock;
	LIST_ENTRY mList;
	ULONG mCount;
	// mInvalid is the 0th bit of mCount
}FLT_MUTEX_LIST_HEAD, *PFLT_MUTEX_LIST_HEAD;
ASSERT_SZ(FLT_MUTEX_LIST_HEAD, 0x50)

typedef struct _FLTPP_LOOKASIDE_LIST {
	PNPAGED_LOOKASIDE_LIST P;
	PNPAGED_LOOKASIDE_LIST L;
}FLTPP_LOOKASIDE_LIST, *PFLTPP_LOOKASIDE_LIST;
ASSERT_SZ(FLTPP_LOOKASIDE_LIST, 0x10)

typedef struct _FLT_PRCB {
	FLTPP_LOOKASIDE_LIST PPIrpCtrlLookasideLists[2];
}FLT_PRCB, *PFLT_PRCB;

typedef struct _FLTP_IRPCTRL_STACK_PROFILER {
	PVOID Frame;
	ULONG Profile[10];
	KTIMER timer;
	KDPC Dpc;
	WORK_QUEUE_ITEM WorkItem;
	FAST_MUTEX Mutex;
	ULONG WorkItemFlags;
	ULONG Flags;
	ULONG AllocCount;
}FLTP_IRPCTRL_STACK_PROFILER, * PFLTP_IRPCTRL_STACK_PROFILER;

typedef struct _FLTP_FRAME {
	DWORD64 type;
	LIST_ENTRY Links;
	ULONG FrameId;
	UNICODE_STRING AltitudeIntervalLow;
	UNICODE_STRING AltitudeIntervalHigh;
	UCHAR LargeIrpCtrlStackSize;
	UCHAR SmallIrpCtrlStackSize;
	FLT_RESOURCE_LIST_HEAD RegisteredFilters;
	FLT_RESOURCE_LIST_HEAD AttachedVolumes;
	LIST_ENTRY MountingVolumes;
	FLT_MUTEX_LIST_HEAD AttachedFileSystems;
	FLT_MUTEX_LIST_HEAD ZombiedFltObjectContexts;
	PVOID64 KtmResourceManagerHandle;
	PKRESOURCEMANAGER KtmResourceManager;
	ERESOURCE FilterUnloadLock;
	FAST_MUTEX DeviceObjectAttachLock;
	PFLT_PRCB Prcb;
	PVOID PrcbPoolToFree;
	PVOID LookasidePoolToFree;
	FLTP_IRPCTRL_STACK_PROFILER IrpCtrlStackProfiler;
	NPAGED_LOOKASIDE_LIST SmallIrpCtrlLookasideList;
	NPAGED_LOOKASIDE_LIST LargeIrpCtrlLookasideList;
	PVOID ReserveIrpCtrls; // fuck that define it yourself
} FLTP_FRAME, *PFLTP_FRAME;

typedef struct _FLT_OBJECT {
	ULONG Flags;
	ULONG PointerCount;
	EX_RUNDOWN_REF RundownRef;
	LIST_ENTRY PrimaryLink;
	GUID UniqueIdenfitier;
} FLT_OBJECT, *PFLT_OBJECT;

typedef struct _FLT_FILTER {
	FLT_OBJECT Base;
	PVOID Frame;
	UNICODE_STRING Name;
	UNICODE_STRING DefaultAltitude;
	DWORD64 Flags;
	PDRIVER_OBJECT DriverObject;
	FLT_RESOURCE_LIST_HEAD InstanceList;
	PVOID VerifierExtension;
	LIST_ENTRY VerifiedFiltersLink;
	PULONG FilterUnload;
	PULONG InstanceSetup;
	PULONG InstanceQueryTeardown;
	PVOID InstanceTeardownStart;
	PVOID InstanceTeardownComplete;
	PVOID SupportedContextsListHead;
	PVOID SupportedContexts[7];
	PVOID PreVolumeMount;
	PVOID PostVolumeMount;
	PVOID GenerateFileName;
	PVOID NormalizeNameComponent;
	PVOID NormalizeNameComponentEx;
	PVOID NormalizeContextCleanup;
	PVOID KtmNotification;
	PVOID SectionNotification;
	PFLT_OPERATION_REGISTRATION Operations;
	PVOID OldDriverUnload;
	FLT_MUTEX_LIST_HEAD ActiveOpens;
	FLT_MUTEX_LIST_HEAD ConnectionList;
	FLT_MUTEX_LIST_HEAD PortList;
	EX_PUSH_LOCK PortLock;
} FLT_FILTER, *PFLT_FILTER;

typedef struct _CALLBACK_NODE {
	LIST_ENTRY CallbackLinks;
#ifdef _KERNEL_MODE
	PFLT_INSTANCE lpInstance;
#else 
	PVOID lpInstance;
#endif
	PVOID PreOperation;
	PVOID PostOperation;
	PVOID GenerateFileName;
	PVOID NormalizeNameComponent;
	PVOID NormalizeNameComponentEx;
	PVOID NormalizeContextCleanup;
	DWORD64 Flags;
}CALLBACK_NODE, *PCALLBACK_NODE;

typedef struct _FLT_INSTANCE {
	FLT_OBJECT Base;
	PEX_RUNDOWN_REF_CACHE_AWARE OperationRundownRef;
	PVOID lpFltVolume;
	PFLT_FILTER Filter;
	DWORD64 Flags;
	UNICODE_STRING Altitude;
	UNICODE_STRING Name;
	LIST_ENTRY FilterLink;
	EX_PUSH_LOCK ContextLock;
	PVOID lpContext;
	PVOID TransactionContexts;
	PVOID TrackCompletionNodes;
	PCALLBACK_NODE CallbackNodes[50];
}FLT_INSTANCE, *PFLT_INSTANCE;