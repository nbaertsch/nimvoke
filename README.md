# nimvoke
Indirect syscalls + DInvoke and made simple.

Designed to be imported directly into your own Nim projects, _nimvoke_ uses macros to absract away the details of making indirect system calls and DInvoke-style delegate declarations. This library is meant to be easy to use and relatively op-sec friendly out-of-the-box. Function and library names used in the macro's are hashed at compile-time, and SSN's and `syscall` instruction addresses are retrieved regardless of any hooks. All syscalls go through the correct `syscall` instruction in `ntdll.dll`.
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
All Nim binaries will import a set of core Win32 functions. All other Win32 functions are resolved via `dynlib` which usus `GetProcAddress` and `LoadLibraryA` to resolve functions at runtime. This DInvoke implementation can prevent exposing _new_ functions that aren't used by other code (be that the nim runtime/GC or stdlib code importing via dynlib), but cannot remove Nim's core imports or alter the behavior of the std or 3rd party libraries.

### Syscalls
On import, `nimvoke/syscalls` will parse the EAT of `ntdll.dll` to find all syscall's and extract the needed data. Information on all syscalls is stored in memory. 
```nim
type
    Syscall* = object
        pName*: PCHAR
        ord*: WORD
        pFunc*: PVOID
        pSyscall*: PVOID = NULL
        ssn*: WORD
        hooked*: bool
...
syscallSeq: seq[Syscall] # stores all syscall data
syscallTable* = initTable[string, ptr Syscall]() # maps syscall `Zw` hashed-name to `Syscall` object's in the `syscallSeq`
```

SSN retrival is done by sorting all syscalls by their address and counting them. This method should work regardless of any hooking. No function name strings are stored in memory, but a pointer to the function name strings in the EAT of `ntdll.dll` is held for calculating hashes.

Syscalls use a single trampoline (from [FreshyCalls](https://github.com/crummie5/FreshyCalls)) to move the SSN to `eax`, prepare the arguments, and jump to the correct `syscall` instruction in `ntdll.dll`.
This trampoline is allocated on a new private heap.

If you want to run code before this syscall initialization code (like for sandbox evasion or enviornmental keying), you need to call it before the `import nimvoke/syscalls` statement in your code.

# Future Work
- [ ] x86 support
- [ ] add more robust error handling and load libraries if they are missing from the process
- [ ] include synthetic stack-frame spoofing

Got suggestions? Open an issue! PR's also welcome.

# Shoutouts
- [FreshyCalls](https://github.com/crummie5/FreshyCalls) and [rust_syscalls](https://github.com/janoglezcampos/rust_syscalls) for providing 'arg-shifting' syscall trampolines.
- [S3cur3Th1sSh1t](https://twitter.com/ShitSecure) for the idea
- [MrUn1k0d3r](https://twitter.com/MrUn1k0d3r) for the great learning material and community
- [Sektor7](https://institute.sektor7.net/) for solid training
