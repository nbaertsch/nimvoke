# nimvoke
DInvoke and indirect syscalls made easy.

Designed to imported directly into your own Nim projects, nimvoke absracts all the details of making indirect system calls and DInvoke-style delegate declarations behind easy to use macros. Function and library names are hashed at copmile-time.

## Usage
Simply import the relevant library and call the corresponding macro. See `examples` for more details.

DInvoke:
```nim
import winim/lean
import nimvoke/dinvoke

dinvokeDefine(
        ZwAllocateVirtualMemory,
        "ntdll.dll",
        proc (ProcessHandle: Handle, BaseAddress: PVOID, ZeroBits: ULONG_PTR, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.stdcall.}
    )

var
        hProcess: HANDLE = 0xFFFFFFFFFFFFFFFF
        shellcodeSize: SIZE_T = 1000
        baseAddr: PVOID
        status: NTSTATUS

status = ZwAllocateVirtualMemory(
    hProcess,
    &baseAddr,
    0,
    &shellcodeSize,
    MEM_RESERVE or MEM_COMMIT,
    PAGE_READWRITE)
```

Syscalls:
```nim
import winim/lean
import nimvoke/syscalls

var
        hProcess: HANDLE = 0xFFFFFFFFFFFFFFFF
        shellcodeSize: SIZE_T = 1000
        baseAddr: PVOID
        status: NTSTATUS

status = syscall(NtAllocateVirtualMemory,
            hProcess,
            &baseAddr,
            0,
            &shellcodeSize,
            MEM_RESERVE or MEM_COMMIT,
            PAGE_READWRITE
        )
```

## Important Op-Sec Notes

### DInvoke
All Nim binaries will import a set of 'core' functions. All other functions are resolved via `dynlib` which usus `GetProcAddress` and `LoadLibraryA` to resolve functions at runtime. This DInvoke implementation can prevent exposing _new_ functions that aren't used by other code (be that the nim runtime/GC or stdlib code importing via dynlib).

### Syscalls
On import, `nimvoke/syscalls` will parse the EAT of `ntdll.dll` to find all syscall's and extract the needed data. Information on syscalls is stored in memory. SSN retrival is done by sorting all syscalls by their address and counting them. This method should work regardless of any hooking. No function name strings are stored in memory, but a pointer to the function name strings in the EAT of `ntdll.dll` is held for calculating hashes.
