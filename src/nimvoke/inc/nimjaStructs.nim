import winim/lean

## Types for all things Windows
## everything prepended with `NIMJA` is derived from windbg by myself.

type
    NIMJA_RTL_BITMAP* {.pure.} = object
        SizeOfBitMap*: WORD
        Buffer*: PVOID
    
    NIMJA_PEB* {.pure.} = object
        InheritedAddressSpace*: BYTE
        ReadImageFileExecOptions*: BYTE
        BeingDebugged*: BYTE
        BitField*: BYTE
        #[ BitField
        +0x003 ImageUsesLargePages : Pos 0, 1 Bit
        +0x003 IsProtectedProcess : Pos 1, 1 Bit
        +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
        +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
        +0x003 IsPackagedProcess : Pos 4, 1 Bit
        +0x003 IsAppContainer   : Pos 5, 1 Bit
        +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
        +0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
        ]#
        Padding0*: DWORD
        Mutant*: PVOID 
        ImageBaseAddress*: PVOID 
        Ldr*: PPEB_LDR_DATA
        ProcessParameters*: PRTL_USER_PROCESS_PARAMETERS
        SubSystemData*: PVOID
        ProcessHeap*: PVOID
        FastPebLock*: PRTL_CRITICAL_SECTION
        AtlThunkSListPtr*: PSLIST_HEADER
        IFEOKey*: PVOID
        CrossProcessFlags*: DWORD
        #[ CrossProcessFlags
        +0x050 ProcessInJob     : Pos 0, 1 Bit
        +0x050 ProcessInitializing : Pos 1, 1 Bit
        +0x050 ProcessUsingVEH  : Pos 2, 1 Bit
        +0x050 ProcessUsingVCH  : Pos 3, 1 Bit
        +0x050 ProcessUsingFTH  : Pos 4, 1 Bit
        +0x050 ProcessPreviouslyThrottled : Pos 5, 1 Bit
        +0x050 ProcessCurrentlyThrottled : Pos 6, 1 Bit
        +0x050 ProcessImagesHotPatched : Pos 7, 1 Bit
        +0x050 ReservedBits0    : Pos 8, 24 Bits
        ]#
        Padding1*: DWORD
        KernelCallbackTable*: PVOID # UNION UserSharedInfoPtr*: PVOID
        SystemReserved*: DWORD
        AtlThunkSListPtr32*: DWORD
        ApiSetMap*: PVOID
        TlsExpansionCounter*: DWORD
        Padding2*: DWORD
        TlsBitmap*: ptr NIMJA_RTL_BITMAP
        TlsBitmapBits*: DWORD64
        ReadOnlySharedMemoryBase*: PVOID
        SharedData*: PVOID
        ReadOnlyStaticServerData*: PVOID
        AnsiCodePageData*: PVOID
        OemCodePageData*: PVOID
        UnicodeCaseTableData*: PVOID
        NumberOfProcessors*: DWORD
        NtGlobalFlag*: DWORD
        CriticalSectionTimeout*: LARGE_INTEGER
        HeapSegmentReserve*: DWORD64
        HeapSegmentCommit*: DWORD64
        HeapDeCommitTotalFreeThreshold*: DWORD64
        HeapDeCommitFreeBlockThreshold*: DWORD64
        NumberOfHeaps*: DWORD
        MaximumNumberOfHeaps*: DWORD
        ProcessHeaps*: ptr PVOID
        GdiSharedHandleTable*: PVOID
        ProcessStarterHelper*: PVOID
        GdiDCAttributeList*: DWORD
        Padding3*: DWORD
        LoaderLock*: PRTL_CRITICAL_SECTION
        OSMajorVersion*: DWORD
        OSMinorVersion*: DWORD
        OSBuildNumber*: WORD
        OSCSDVersion*: WORD
        OSPlatformId*: DWORD
        ImageSubsystem*: DWORD
        ImageSubsystemMajorVersion*: DWORD
        ImageSubsystemMinorVersion*: DWORD
        Padding4*: DWORD
        ActiveProcessAffinityMask*: DWORD64
        GdiHandleBuffer*: array[60, DWORD]
        PostProcessInitRoutine*: PVOID
        TlsExpansionBitmap*: ptr NIMJA_RTL_BITMAP
        TlsExpansionBitmapBits*: array[32, DWORD]
        SessionId*: DWORD
        Padding5*: DWORD
        AppCompatFlags*: ULARGE_INTEGER
        AppCompatFlagsUser*: ULARGE_INTEGER
        pShimData*: PVOID
        AppCompatInfo*: PVOID
        CSDVersion*: UNICODE_STRING
        ActivationContextData*: PVOID # ptr ACTIVATION_CONTEXT_DATA
        ProcessAssemblyStorageMap*: PVOID # ptr ASSEMBLY_STORAGE_MAP
        SystemDefaultActivationContextData*: PVOID # ptr ACTIVATION_CONTEXT_DATA
        SystemAssemblyStorageMap*: PVOID # ptr ASSEMBLY_STORAGE_MAP
        MinimumStackCommit*: DWORD64
        SparePointers*: array[2, PVOID]
        PatchLoaderData*: PVOID
        ChpeV2ProcessInfo*: PVOID # ptr CHPEV2_PROCESS_INFO
        AppModelFeatureState*: DWORD
        SpareUlongs*: array[2, DWORD]
        ActiveCodePage*: WORD
        OemCodePage*: WORD
        UseCaseMapping*: WORD
        UnusedNlsField*: WORD
        WerRegistrationData*: PVOID
        WerShipAssertPtr*: PVOID
        EcCodeBitMap*: PVOID
        pImageHeaderHash*: PVOID
        TracingFlags*: DWORD
        #[ Tracing Flags
        +0x378 HeapTracingEnabled : Pos 0, 1 Bit
        +0x378 CritSecTracingEnabled : Pos 1, 1 Bit
        +0x378 LibLoaderTracingEnabled : Pos 2, 1 Bit
        +0x378 SpareTracingBits : Pos 3, 29 Bits
        ]#
        Padding6*: DWORD
        CsrServerReadOnlySharedMemoryBase*: DWORD64
        TppWorkerpListLock*: DWORD64
        TppWorkerpList*: LIST_ENTRY
        WaitOnAddressHashTable*: array[128, PVOID]
        TelemetryCoverageHeader*: PVOID
        CloudFileFlags*: DWORD
        CloudFileDiagFlags*: DWORD
        PlaceholderCompatibilityMode*: CHAR
        PlaceholderCompatibilityModeReserved*: array[7, CHAR]
        LeapSecondData*: PVOID # ptr LEAP_SECOND_DATA
        LeapSecondFlags*: DWORD
        #[LeapSecondFlags
        +0x7c0 SixtySecondEnabled : Pos 0, 1 Bit
        +0x7c0 Reserved         : Pos 1, 31 Bits
        ]#
        NtGlobalFlag2*: DWORD
        ExtendedFeatureDisableMask*: DWORD64

    USTRING* {.bycopy.} = object
        Length*: DWORD
        MaximumLength*: DWORD
        Buffer*: PVOID

    NIMJA_TEB* {.pure.} = object
        Reserved1*: array[12, PVOID]
        ProcessEnvironmentBlock*: ptr NIMJA_PEB
        Reserved2*: array[399, PVOID]
        Reserved3*: array[1952, BYTE]
        TlsSlots*: array[64, PVOID]
        Reserved4*: array[8, BYTE]
        Reserved5*: array[26, PVOID]
        ReservedForOle*: PVOID
        Reserved6*: array[4, PVOID]
        TlsExpansionSlots*: PVOID

    NIMJA_RTL_BALANCED_NODE* {.pure.} = object
        Left: ptr NIMJA_RTL_BALANCED_NODE
        Right: ptr NIMJA_RTL_BALANCED_NODE
        ParentValue: DWORD
    
    #[
    NIMJA_LDR_DLL_LOAD_REASON* {.pure.} = enum
        LoadReasonUnknown = -1
        LoadReasonStaticDependency = 0
        LoadReasonStaticForwarderDependency = 1
        LoadReasonDynamicForwarderDependency = 2
        LoadReasonDelayloadDependency = 3
        LoadReasonDynamicLoad = 4
        LoadReasonAsImageLoad = 5
        LoadReasonAsDataLoad = 6
        LoadReasonEnclavePrimary = 7
        LoadReasonEnclaveDependency = 8
        LoadReasonPatchImage = 9
    ]#

    NIMJA_LDR_DATA_TABLE_ENTRY* {.pure.} = object
        InLoadOrderLinks*: LIST_ENTRY
        InMemoryOrderLinks*: LIST_ENTRY
        InInitializationOrderLinks*: LIST_ENTRY
        DllBase*: PVOID
        EntryPoint*: PVOID
        SizeOfImage*: DWORD
        Pad1*: DWORD
        FullDllName*: UNICODE_STRING
        BaseDllName*: UNICODE_STRING
        Reserved5*: array[3, PVOID]
        union1*: LDR_DATA_TABLE_ENTRY_UNION1
        TimeDateStamp*: ULONG
        EntryPointActivationContext*: PVOID
        Lock*: PVOID
        DdagNode*: PVOID
        NodeModuleLink*: LIST_ENTRY
        LoadContext*: PVOID
        ParentDllBase*: PVOID
        SwitchBackContext*:PVOID
        BaseAddressIndexNode*: NIMJA_RTL_BALANCED_NODE
        MappingInfoIndexNode*: NIMJA_RTL_BALANCED_NODE
        OriginalBase*: DWORD
        LoadTime*: LARGE_INTEGER
        BaseNameHashValue*: WORD
        LoadReason*: WORD #NIMJA_LDR_DLL_LOAD_REASON
        ReferenceCount*: WORD
        DependentLoadFlags*:WORD
        SigningLevel*: UCHAR
        CheckSum*:DWORD
        ActivePatchImageBase*: PVOID
        #HotPatchState*: LDR_HOT_PATCH_STATE
    
    
    USER_THREAD_START_ROUTINE* = proc (ThreadParameter: PVOID): NTSTATUS

    PUSER_THREAD_START_ROUTINE* = ptr USER_THREAD_START_ROUTINE

    PS_ATTRIBUTE* {.pure.} = object
        Attribute: ULONG_PTR
        Size: SIZE_T
        ValuePtr: PVOID
        ReturnLength: PSIZE_T

    PPS_ATTRIBUTE_LIST* {.pure.} = object
        TotalLength: SIZE_T
        Attributes: UncheckedArray[PS_ATTRIBUTE]