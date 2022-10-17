#pragma once
#include <Windows.h>
#include <winnt.h>
#include <winternl.h>

static BYTE prelude1[7]{
	0x4D, 0x8d, 0x4b, 0xf0, // lea r9, [r11-10h]
	0x45, 0x33, 0xc0 // xor r8d, r8d
};

static BYTE prelude2[9] = {
	0x44, 0x8B, 0xC5,
	0x48, 0x8B, 0xD6,
	0x48, 0x8B, 0xCF
};

static BYTE prelude3[9] = {
	0x48, 0x83, 0xEC, 0x20, //sub rsp, 20h
	0x44, 0x8B,	0x7C, 0x24, 0x70 //mov r15d, [rsp+48h+arg_20]
};

#pragma pack(push)
#pragma pack(1)
typedef struct _call_rel32 {
	BYTE opcode;
	LONG offset;
}call_rel32, * pcall_rel32;

typedef struct _lea_rel32 {
	BYTE lea[3];
	LONG offset;
}lea_rel32, * plea_rel32;
#pragma pack(pop)

__forceinline HMODULE getK32() {
	HMODULE r;
#ifdef _WIN64
	PPEB _ppeb = (PPEB)__readgsqword(0x60);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink + 0x20);
#else
	PPEB _ppeb = (PPEB)__readfsdword(0x30);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink + 0x10);
#endif
	return r;
}
__forceinline HMODULE getNtdll() {
	HMODULE r;
#ifdef _WIN64
	PPEB _ppeb = (PPEB)__readgsqword(0x60);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink + 0x20);
#else
	PPEB _ppeb = (PPEB)__readfsdword(0x30);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink + 0x10);
#endif
	return r;
}

#pragma intrinsic(memcmp)
static PVOID findPattern(PVOID buf, PBYTE pattern, ULONG ulLength) {
	PBYTE pBuf = (PBYTE)buf;

	while (TRUE) {
		// check for return "ret; int3"
		DWORD wCheckRet = *(PDWORD)pBuf;
		if (wCheckRet == 0xCCCCCCC3) {
			return NULL;
		}

		BOOL res = !memcmp(pBuf, pattern, ulLength);

		if (res) {
			return pBuf;
		}

		pBuf += 1;
	}
}

typedef DWORD APIHASH;
typedef ULONG MODULEHASH;

#define MODULEHASH_NTDLL ((MODULEHASH)0xf46857d4)
#define MOD_ADLER 65521

constexpr DWORD cexpr_adler32(const char* src) {
	DWORD result_a = 1;
	DWORD result_b = 0;
	for (int i = 0; src[i] != 0; i++) {
		// calculate result_a
		result_a = (result_a + (DWORD)src[i]) % MOD_ADLER;
		result_b = (result_b + result_a) % MOD_ADLER;
	}
	return (result_b << 16) | result_a;
}

static __forceinline DWORD static_adler32(char* src) {
	DWORD result_a = 1;
	DWORD result_b = 0;
	for (int i = 0; src[i] != 0; i++) {
		// calculate result_a
		result_a = (result_a + (DWORD)src[i]) % MOD_ADLER;
		result_b = (result_b + result_a) % MOD_ADLER;
	}
	return (result_b << 16) | result_a;
}

constexpr MODULEHASH cexpr_x65599(const char* src) {
	MODULEHASH mhModuleHash = 0;
	for (int i = 0; src[i]; i++) {

		if (src[i] >= 'a' && src[i] <= 'z') {
			mhModuleHash = 65599 * mhModuleHash + (src[i] - 0x20);
		}
		else {
			mhModuleHash = 65599 * mhModuleHash + src[i];
		}

	}
	return mhModuleHash;
}




static constexpr APIHASH glb_hashGetProcAddress = cexpr_adler32("GetProcAddress");
static constexpr APIHASH glb_hashLoadLibraryA = cexpr_adler32("LoadLibraryA");
static constexpr APIHASH glb_hashGetModuleHandleA = cexpr_adler32("GetModuleHandleA");
static constexpr APIHASH glb_hashRtlAllocateHeap = cexpr_adler32("RtlAllocateHeap");
static constexpr APIHASH glb_hashRtlFreeHeap = cexpr_adler32("RtlFreeHeap");
static constexpr APIHASH glb_hashLdrGetDllHandleByName = cexpr_adler32("LdrGetDllHandleByName");

typedef void* (WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef void* (WINAPI* pRtlAllocateHeap)(HANDLE, DWORD, SIZE_T);
typedef BOOL(WINAPI* pRtlFreeHeap)(PVOID, DWORD, PVOID);


static pRtlAllocateHeap glb_stubRtlAllocateHeap = NULL;
static pRtlFreeHeap glb_stubRtlFreeHeap = NULL;
static pGetProcAddress glb_stubGetProcAddress = NULL;
static pLoadLibraryA glb_stubLoadLibraryA = NULL;
static pGetModuleHandleA glb_stubGetModuleHandleA = NULL;



typedef struct _peb_ldr {
	HMODULE base;
	void* p_eat_strtbl;
	PDWORD p_eat_ptrtbl;
	PWORD p_eat_ordtbl;
	size_t num_exp;
	BOOL init;
	BOOL _eat_from_base() {
		IMAGE_DOS_HEADER* _dos = (IMAGE_DOS_HEADER*)this->base;
		if (_dos->e_magic != IMAGE_DOS_SIGNATURE)
			return FALSE;
		IMAGE_NT_HEADERS* _nt = (IMAGE_NT_HEADERS*)((size_t)this->base + _dos->e_lfanew);
		if (_nt->Signature != IMAGE_NT_SIGNATURE)
			return FALSE;

		IMAGE_EXPORT_DIRECTORY* _export = (IMAGE_EXPORT_DIRECTORY*)(_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (size_t)this->base);
		PDWORD funcTbl = (PDWORD)(_export->AddressOfFunctions + (size_t)this->base);
		void* nameTbl = (void*)(_export->AddressOfNames + (size_t)this->base);
		PWORD ordTbl = (PWORD)(_export->AddressOfNameOrdinals + (size_t)this->base);
		this->p_eat_ptrtbl = funcTbl;
		this->p_eat_strtbl = nameTbl;
		this->p_eat_ordtbl = ordTbl;
		this->num_exp = _export->NumberOfFunctions;
		return TRUE;
	}

	/*
	Passing NULL as the dll name signifies you're walking the export table
	of Kernel32.dll
	*/
	_peb_ldr(const char* dll) : init(FALSE), base(NULL), p_eat_ptrtbl(NULL), p_eat_strtbl(NULL) {
		this->num_exp = 0;
		this->p_eat_ordtbl = 0;

		// BEGIN INITIALIZATION
		if (!(glb_stubGetModuleHandleA && glb_stubLoadLibraryA && glb_stubGetProcAddress)) {
			this->base = getK32();
			if (!this->_eat_from_base()) { // set up the EAT information
				return;
			}

			glb_stubGetModuleHandleA = (pGetModuleHandleA)this->get(glb_hashGetModuleHandleA);
			glb_stubLoadLibraryA = (pLoadLibraryA)this->get(glb_hashLoadLibraryA);
			if (!(glb_stubGetModuleHandleA && glb_stubLoadLibraryA)) {
				return;
			}

		}
		// END INITIALIZATION
		if (dll != NULL) { // if dll IS null, this->base == Kernel32
			this->base = glb_stubGetModuleHandleA(dll);
			if (this->base == NULL) {
				this->base = glb_stubLoadLibraryA(dll);
				if (this->base == NULL)
					return;
			}
		}
		else {
			this->base = getK32();
		}

		this->init = this->_eat_from_base();
		return;
	}

	_peb_ldr(LPVOID lpDllBase) : init(FALSE), base(NULL), p_eat_ptrtbl(NULL), p_eat_strtbl(NULL) {
		this->num_exp = 0;
		this->p_eat_ordtbl = 0;

		if (lpDllBase != NULL) { // if dll IS null, this->base == Kernel32
			this->base = (HMODULE)lpDllBase;
		}
		else {
			this->base = getK32();
		}

		this->init = this->_eat_from_base();
		return;
	}

	_peb_ldr(MODULEHASH mhModuleHash) : init(FALSE), base(NULL), p_eat_ptrtbl(NULL), p_eat_strtbl(NULL), p_eat_ordtbl(NULL), num_exp(0) {
		this->init = FALSE;
		ULONG ulHashTableOffset = mhModuleHash & 0x1f;
		HMODULE hNtdll = getNtdll();

		_peb_ldr nt_ldr = _peb_ldr(hNtdll);
		if (!nt_ldr.init) {
			return;
		}


		PBYTE pLdrGetDllHandleByName = (PBYTE)nt_ldr.get(glb_hashLdrGetDllHandleByName);
		PVOID pPattern = findPattern(pLdrGetDllHandleByName, prelude1, sizeof(prelude1));
		if (!pPattern) {
			return;
		}

		pcall_rel32 pcall_LdrpFindLoadedDllByName = (pcall_rel32)((PBYTE)pPattern + sizeof(prelude1));

		PBYTE pLdrpFindLoadedDllByName = (PBYTE)pPattern + sizeof(prelude1) + pcall_LdrpFindLoadedDllByName->offset + sizeof(call_rel32);

		pPattern = findPattern(pLdrpFindLoadedDllByName, prelude2, sizeof(prelude2));
		if (!pPattern) {
			return;
		}

		pcall_rel32 pcall_LdrpFindLoadedDllByNameLockHeld = (pcall_rel32)((PBYTE)pPattern + sizeof(prelude2));

		PVOID pLdrpFindLoadedDllByNameLockHeld = (PBYTE)pPattern + sizeof(prelude2) + pcall_LdrpFindLoadedDllByNameLockHeld->offset + sizeof(call_rel32);

		// now find the hash table
		pPattern = findPattern(pLdrpFindLoadedDllByNameLockHeld, prelude3, sizeof(prelude3));
		if (!pPattern) {
			return;
		}

		plea_rel32 plea_LdrpHashTable = (plea_rel32)((PBYTE)pPattern + sizeof(prelude3));
		PLIST_ENTRY pLdrpHashTable = (PLIST_ENTRY)((PBYTE)pPattern + sizeof(prelude3) + plea_LdrpHashTable->offset + sizeof(lea_rel32));

		PVOID pHashTableData = (PVOID)pLdrpHashTable[ulHashTableOffset].Flink;
		PLDR_DATA_TABLE_ENTRY pLdrDteModule = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pHashTableData - 0x70);

		this->base = (HMODULE)pLdrDteModule->DllBase;
		this->init = this->_eat_from_base();
		return;
	}

	static void* operator new(size_t block_size) {
		return HeapAlloc(GetProcessHeap(), 0, block_size);
	}

	void* get(DWORD hash) {
		void* string_tbl_iter = this->p_eat_strtbl;
		for (unsigned int i = 0; i < this->num_exp; i++) {
			DWORD name_offset = *(DWORD*)string_tbl_iter;
			char* namePtr = ((char*)this->base + name_offset);
			auto x = static_adler32(namePtr);
			if (static_adler32(namePtr) == hash) {
				DWORD fn_va = this->p_eat_ptrtbl[this->p_eat_ordtbl[i]];
				void* fn = (void*)((size_t)this->base + (DWORD)fn_va);
				return fn;
			}
			string_tbl_iter = (void*)((unsigned char*)string_tbl_iter + sizeof(DWORD));
		}
		return NULL;
	}
} _peb_ldr, * _ppeb_ldr;