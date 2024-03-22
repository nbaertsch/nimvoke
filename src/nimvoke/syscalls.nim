## File: syscalls.nim
## Author: nbaertsch
## 
## This is 'delegate-less' syscall implementation leveraging prior work by Freshy Calls and Rust_Syscalls projoects.
## This file implements the syscall number and syscall instruction address retrieval for _all_ syscall functions, and
## includes a macro for calling the syscalls simply and easily. The `initSyscall` proc does the syscall set-up and
## runs once on first import. It uses 'nimvoke/dinvoke' to allocate the syscall trampoline on a new heap. If you want
## to run code before this proc is called, you must import 'nimvoke/syscalls' _after_ any preamble code.
## Both Freshy Calls and Rust_Syscalls trampolines are available, Freshy Calls is currently in use.

    
import std/[tables, macros]
from algorithm import sortedByIt
from winim/lean import PAGE_EXECUTE_READ, PCHAR, WORD, DWORD, PVOID, NULL, SIZE_T, HANDLE, LPVOID, PDWORD, HEAP_GENERATE_EXCEPTIONS, NTSTATUS, BOOL, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT
from ptr_math import `+`

import inc/common
import dinvoke

export common

type
    Syscall* = object
        pName*: PCHAR
        ord*: WORD
        pFunc*: PVOID
        pSyscall*: PVOID = NULL
        ssn*: WORD
        hooked*: bool 
    doSyscallFreshy_t = proc (ssn: uint32, jmpAddr: uint64): NTSTATUS {.varargs, stdcall.}
    doSyscallRusty_t = proc (ssn: uint32, jmpAddr: uint64, nArgs: uint32): NTSTATUS {.varargs, stdcall.}

macro syscall*(funcName: untyped, args: varargs[untyped]): untyped =
    ## Convenince macro for calling indirect syscall's by name.
    ## Syscall numbers retrieved by sort-and-count. This macro hides the
    ## details of syscall retrieval and calling from the caller.
    var funcNameStr = funcName.strVal
    if funcNameStr[0..1] == "Nt":
        funcNameStr[0] = 'Z'
        funcNameStr[1] = 'w'
    quote do:
        cast[NTSTATUS](
            doSyscall(syscallTable[hashAsciiStatic(`funcNameStr`)].ssn.uint16,
                cast[uint64](syscallTable[hashAsciiStatic(`funcNameStr`)].pSyscall),
                `args`
            )
        )

# dinvoke defines for all-the-things pre-syscall's
dinvokeDefine(
    HeapCreate,
    "Kernel32.dll",
    proc (flOptions: DWORD, dwInitialSize: SIZE_T, dwMaximumSize: SIZE_T): HANDLE {.stdcall.}
)

dinvokeDefine(
    HeapAlloc,
    "Kernel32.dll",
    proc (hHeap: HANDLE, dwFlags: DWORD, dwBytes: SIZE_T): LPVOID {.stdcall.}
)

dinvokeDefine(
    VirtualProtect,
    "Kernel32.dll",
    proc (lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD): BOOL {.stdcall.}
)

var 
    initialized = false
    TRAMPOLINE_SIZE_FRESHY = 59
    TRAMPOLINE_SIZE_RUSTY = 81
    doSyscall*: doSyscallFreshy_t # change to `doSyscallRusty_t` rusty to use the rust_syscall asm stub instead of freshy calls stub. Different args!
    syscallSeq: seq[Syscall] # stores all syscall data
    syscallTable* = initTable[string, ptr Syscall]() # maps syscall `Zw` hashed-name to `Syscall` object's in the `syscallSeq`
    hSyscallTrampHeap: HANDLE = HeapCreate(HEAP_GENERATE_EXCEPTIONS, 0, 0) # never destroyed - remains for life of process. Trampoline allocated here.
    syscallStubSize: SIZE_T

# Freshycalls
proc getSyscallTrampolineFreshy(): ptr UncheckedArray[byte] = 
    ## Returns a pointer to the R-X asm stub used for making syscalls. Asm refference: https://github.com/crummie5/FreshyCalls/blob/master/syscall.cpp
    ## Allocation is done on a private heap created specifically for this purpose.
    
    # Allocate some space on the private heap for our syscall trampoline
    var syscallTrampoline = cast[ptr UncheckedArray[byte]](HeapAlloc(hSyscallTrampHeap, 0, TRAMPOLINE_SIZE_FRESHY))

    # Syscall stub source: https://github.com/crummie5/FreshyCalls/blob/master/syscall.cpp
    #syscallTrampoline = cast[ptr UncheckedArray[byte]](cast[SIZE_T](syscallTrampoline) + 4)
    syscallTrampoline[0] = byte(0x41) # push r13
    syscallTrampoline[1] = byte(0x55)

    syscallTrampoline[2] = byte(0x41) # push r14
    syscallTrampoline[3] = byte(0x56)

    syscallTrampoline[4] = byte(0x49) # mov r14, rdx
    syscallTrampoline[5] = byte(0x89)
    syscallTrampoline[6] = byte(0xD6)

    syscallTrampoline[7] = byte(0x49) # mov r13, rcx
    syscallTrampoline[8] = byte(0x89)
    syscallTrampoline[9] = byte(0xCD)

    syscallTrampoline[10] = byte(0x4C) # mov rcx, r8
    syscallTrampoline[11] = byte(0x89) 
    syscallTrampoline[12] = byte(0xC1) 

    syscallTrampoline[13] = byte(0x4C) # mov rdx, r9
    syscallTrampoline[14] = byte(0x89) 
    syscallTrampoline[15] = byte(0xCA)
    
    syscallTrampoline[16] = byte(0x4C) # mov r8, [rsp+38h]
    syscallTrampoline[17] = byte(0x8B) 
    syscallTrampoline[18] = byte(0x44)
    syscallTrampoline[19] = byte(0x24)
    syscallTrampoline[20] = byte(0x38)

    syscallTrampoline[21] = byte(0x4C) # mov r9, [rsp+40h]
    syscallTrampoline[22] = byte(0x8B)
    syscallTrampoline[23] = byte(0x4C)
    syscallTrampoline[24] = byte(0x24)
    syscallTrampoline[25] = byte(0x40)

    syscallTrampoline[26] = byte(0x48) # add rsp, 28h
    syscallTrampoline[27] = byte(0x83)
    syscallTrampoline[28] = byte(0xC4)
    syscallTrampoline[29] = byte(0x28)

    syscallTrampoline[30] = byte(0x4C) # lea r11, [rip+0x0C]
    syscallTrampoline[31] = byte(0x8D)
    syscallTrampoline[32] = byte(0x1D)
    syscallTrampoline[33] = byte(0x0C)
    syscallTrampoline[34] = byte(0x00)
    syscallTrampoline[35] = byte(0x00)
    syscallTrampoline[36] = byte(0x00)

    syscallTrampoline[37] = byte(0x41) # call r11
    syscallTrampoline[38] = byte(0xFF)
    syscallTrampoline[39] = byte(0xD3)

    syscallTrampoline[40] = byte(0x48) # sub rsp, 28h
    syscallTrampoline[41] = byte(0x83)
    syscallTrampoline[42] = byte(0xEC)
    syscallTrampoline[43] = byte(0x28)

    syscallTrampoline[44] = byte(0x41) # pop r14
    syscallTrampoline[45] = byte(0x5E)

    syscallTrampoline[46] = byte(0x41) # pop r13
    syscallTrampoline[47] = byte(0x5D)

    syscallTrampoline[48] = byte(0xC3) # ret

    syscallTrampoline[49] = byte(0x4C) # mov rax, r13
    syscallTrampoline[50] = byte(0x89)
    syscallTrampoline[51] = byte(0xE8)

    syscallTrampoline[52] = byte(0x49) # mov r10, rcx
    syscallTrampoline[53] = byte(0x89)
    syscallTrampoline[54] = byte(0xCA) 
    
    syscallTrampoline[55] = byte(0x41) # jmp r14
    syscallTrampoline[56] = byte(0xFF) 
    syscallTrampoline[57] = byte(0xE6)

    syscallTrampoline[58] = byte(0xC3) # ret
    
    # set the page permission of the trampolines to R-X
    var
        op: DWORD = 0
        success: bool
    success = VirtualProtect(cast[LPVOID](syscallTrampoline), cast[SIZE_T](TRAMPOLINE_SIZE_FRESHY), PAGE_EXECUTE_READ, addr op)
    if not success: echo "[x] Failed to set allocated syscall trampoline stub to R-X"

    return syscallTrampoline

# Rust_syscals
proc getSyscallTrampolineRusty(): ptr UncheckedArray[byte] = 
    # Allocate some space on the private heap for our syscall trampoline
    var syscallTrampoline = cast[ptr UncheckedArray[byte]](HeapAlloc(hSyscallTrampHeap, 0, TRAMPOLINE_SIZE_RUSTY))

    # Syscall stub source: https://github.com/janoglezcampos/rust_syscalls/blob/main/src/syscall.rs
    syscallTrampoline[0] = byte(0x48) # mov    QWORD PTR [rsp-0x8],rsi
    syscallTrampoline[1] = byte(0x89)
    syscallTrampoline[2] = byte(0x74)
    syscallTrampoline[3] = byte(0x24)
    syscallTrampoline[4] = byte(0xf8) 

    syscallTrampoline[5] = byte(0x48) # mov    QWORD PTR [rsp-0x10],rdi
    syscallTrampoline[6] = byte(0x89)
    syscallTrampoline[7] = byte(0x7c) 
    syscallTrampoline[8] = byte(0x24)
    syscallTrampoline[9] = byte(0xf0)

    syscallTrampoline[10] = byte(0x4C) # mov    QWORD PTR [rsp-0x18],r12
    syscallTrampoline[11] = byte(0x89) 
    syscallTrampoline[12] = byte(0x64)
    syscallTrampoline[13] = byte(0x24)
    syscallTrampoline[14] = byte(0xE8)

    syscallTrampoline[15] = byte(0x89) # mov    eax,ecx
    syscallTrampoline[16] = byte(0xC8)

    syscallTrampoline[17] = byte(0x49) # mov    r12,rdx
    syscallTrampoline[18] = byte(0x89)
    syscallTrampoline[19] = byte(0xD4)

    syscallTrampoline[20] = byte(0x4C) # mov    rcx,r8
    syscallTrampoline[21] = byte(0x89)
    syscallTrampoline[22] = byte(0xC1)

    syscallTrampoline[23] = byte(0x4D) # mov    r10,r9
    syscallTrampoline[24] = byte(0x89)
    syscallTrampoline[25] = byte(0xCA)

    syscallTrampoline[26] = byte(0x48) # mov    rdx,QWORD PTR [rsp+0x28]
    syscallTrampoline[27] = byte(0x8B)
    syscallTrampoline[28] = byte(0x54)
    syscallTrampoline[29] = byte(0x24)
    syscallTrampoline[30] = byte(0x28)

    syscallTrampoline[31] = byte(0x4C) # mov    r8,QWORD PTR [rsp+0x30]
    syscallTrampoline[32] = byte(0x8B)
    syscallTrampoline[33] = byte(0x44)
    syscallTrampoline[34] = byte(0x24)
    syscallTrampoline[35] = byte(0x30)

    syscallTrampoline[36] = byte(0x4C) # mov    r9,QWORD PTR [rsp+0x38]
    syscallTrampoline[37] = byte(0x8B) 
    syscallTrampoline[38] = byte(0x4C)
    syscallTrampoline[39] = byte(0x24)
    syscallTrampoline[40] = byte(0x38)

    syscallTrampoline[41] = byte(0x48) # sub    rcx,0x4
    syscallTrampoline[42] = byte(0x83)
    syscallTrampoline[43] = byte(0xE9)
    syscallTrampoline[44] = byte(0x04) 
    
    syscallTrampoline[45] = byte(0x7E) # jle    <skip>
    syscallTrampoline[46] = byte(0x0D)

    syscallTrampoline[47] = byte(0x48) # lea    rsi,[rsp+0x40]
    syscallTrampoline[48] = byte(0x8D) 
    syscallTrampoline[49] = byte(0x74) 
    syscallTrampoline[50] = byte(0x24)
    syscallTrampoline[51] = byte(0x40)

    syscallTrampoline[52] = byte(0x48) # lea    rdi,[rsp+0x28]
    syscallTrampoline[53] = byte(0x8D)
    syscallTrampoline[54] = byte(0x7C) 
    syscallTrampoline[55] = byte(0x24) 
    syscallTrampoline[56] = byte(0x28)

    syscallTrampoline[57] = byte(0xF3) # rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]
    syscallTrampoline[58] = byte(0x48)
    syscallTrampoline[59] = byte(0xA5)

    # skip
    syscallTrampoline[60] = byte(0x4C) # mov    rcx,r12
    syscallTrampoline[61] = byte(0x89)
    syscallTrampoline[62] = byte(0xE1)

    syscallTrampoline[63] = byte(0x48) # mov    rsi,QWORD PTR [rsp-0x8]
    syscallTrampoline[64] = byte(0x8B)
    syscallTrampoline[65] = byte(0x74)
    syscallTrampoline[66] = byte(0x24)
    syscallTrampoline[67] = byte(0xF8)

    syscallTrampoline[68] = byte(0x48) # mov    rdi,QWORD PTR [rsp-0x10]
    syscallTrampoline[69] = byte(0x8B)
    syscallTrampoline[70] = byte(0x7C)
    syscallTrampoline[71] = byte(0x24)
    syscallTrampoline[72] = byte(0xF0)

    syscallTrampoline[73] = byte(0x4C) # mov    r12,QWORD PTR [rsp-0x18]
    syscallTrampoline[74] = byte(0x8B)
    syscallTrampoline[75] = byte(0x64)
    syscallTrampoline[76] = byte(0x24)
    syscallTrampoline[77] = byte(0xE8)

    syscallTrampoline[78] = byte(0xFF) # jmp    rcx
    syscallTrampoline[79] = byte(0xE1)

    syscallTrampoline[80] = byte(0xC3) # ret

    # set the page permission of the trampolines to R-X
    var
        op: DWORD = 0
        success: bool
    success = VirtualProtect(cast[LPVOID](syscallTrampoline), cast[SIZE_T](TRAMPOLINE_SIZE_RUSTY), PAGE_EXECUTE_READ, addr op)
    if not success: echo "[x] Failed to set allocated syscall trampoline stub to R-X"

    return syscallTrampoline

proc initSyscalls() =
    ## Populates a table of syscall data types, sorts the table, 
    ## identifies hooks, and retrieves SSNs and syscall address's
    
    if initialized: return
    var
        modBase = getModuleHandleByHash(hashAsciiStatic("ntdll.dll"))
        dosHeader: IMAGE_DOS_HEADER
        ntHeader: IMAGE_NT_HEADERS
        exportDirectory: IMAGE_EXPORT_DIRECTORY
        exportDirectoryOffset: DWORD 
        pExportFuncTable: PVOID 
        pExportNameTable: PVOID 
        pExportOrdinalTable: PVOID 

    dosHeader = cast[ptr IMAGE_DOS_HEADER](modBase)[]
    ntHeader = cast[ptr IMAGE_NT_HEADERS](modBase + dosHeader.e_lfanew)[]
    exportDirectoryOffset = (ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress
    exportDirectory = cast[ptr IMAGE_EXPORT_DIRECTORY](modBase + exportDirectoryOffset)[]

    pExportFuncTable = cast[PVOID](modBase) + exportDirectory.AddressOfFunctions
    pExportNameTable = cast[PVOID](modBase) + exportDirectory.AddressOfNames
    pExportOrdinalTable = cast[PVOID](modBase) + exportDirectory.AddressOfNameOrdinals

    # populate syscalls with syscall names, name-hashes, func ptrs, and ordinals
    for funcNum in 0..exportDirectory.NumberOfNames:
        var
            syscall: Syscall
            funcName: string

        syscall.pName = cast[PCHAR](modBase + cast[ptr DWORD](pExportNameTable + funcNum * sizeof(DWORD))[])
        syscall.ord = cast[ptr WORD](pExportOrdinalTable + funcNum * sizeof(WORD))[]
        syscall.pFunc = cast[PVOID](modBase + cast[ptr DWORD](pExportFuncTable + syscall.ord.int * sizeof(DWORD))[])

        # syscall's only
        funcName = pCharToString(syscall.pName)
        if (funcName.len < 2) or not (funcName[0..1] == "Zw"):
            continue

        # add to syscall sequence
        syscallSeq.add(syscall)
        
    # Sort the syscall table by function address so we can infer syscall numbers for hooked syscalls later (Halos Gate)
    syscallSeq = syscallSeq.sortedByIt(it.pFunc)

    # Get size of all exported syscall fucnctions (minus the last one...)
    var syscallStubSizes: seq[SIZE_T] = newSeq[SIZE_T](syscallSeq.high)
    for s in 0..(syscallSeq.high-1):
        syscallStubSizes[s] = (cast[SIZE_T](syscallSeq[s+1].pFunc) - cast[SIZE_T](syscallSeq[s].pFunc)) * (sizeof(SIZE_T) / sizeof(DWORD)).int

    # Get size of syscall stub
    syscallStubSize = 2147483647
    for s in 0..(syscallSeq.high-1):
        if syscallStubSizes[s] < syscallStubSize: syscallStubSize = syscallStubSizes[s]

    
    # If the first four bytes aren't `move r10, rcx; mov eax [SSN]` than mark the syscall as hooked
    for s in 0..(syscallSeq.high):
        # Check for mov r10, rcx; mov eax [SSN] 
        if (cast[ptr byte](syscallSeq[s].pFunc)[] == 0x4C) and
            (cast[ptr byte](syscallSeq[s].pFunc + 1)[] == 0x8B) and
            (cast[ptr byte](syscallSeq[s].pFunc + 2)[] == 0xD1) and 
            (cast[ptr byte](syscallSeq[s].pFunc + 3)[] == 0xB8):
                discard

        else: # This syscall is hooked
            syscallSeq[s].hooked = true
            continue

        for i in 0..syscallStubSize:
            # Check for syscall instruction
            if (cast[ptr byte](syscallSeq[s].pFunc + i)[] == 0x0F) and 
                (cast[ptr byte](syscallSeq[s].pFunc + i + 1)[] == 0x05):
                    syscallSeq[s].pSyscall = (syscallSeq[s].pFunc + i)

    # Simply count the syscall's now that they're sorted
    for s in 0..syscallSeq.high:
        syscallSeq[s].ssn = (s).WORD

    # allocate and build indirect syscall trampoline
    doSyscall = cast[doSyscallFreshy_t](cast[PVOID](getSyscallTrampolineFreshy()))
    
    # populate the syscallTable hashmap
    for s in 0..syscallSeq.high:
        syscallTable[syscallSeq[s].pName.pCharToString().hashAscii()] = addr syscallSeq[s]

# called on first import 
initSyscalls()