## File: dinvoke.nim
## Author: nbaertsch
## 
## This is a nim dinvoke implementation that uses compile-time string hashing.

import std/[macros]
from std/strutils import rsplit
from winim/lean import PEB, PPEB, PVOID, LIST_ENTRY, PEB_LDR_DATA, FARPROC, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, DWORD, WORD, SIZE_T, NULL, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, PCHAR
from ptr_math import `+`

import inc/common
import inc/nimjaStructs

export common

macro dinvokeDefine*(funcName: untyped, libName: untyped, funcDef: untyped): untyped =
    ## Defines a new delegate function var `funcName`, of type `funcDef`, and casts the appropriate function ptr to the delegate.
    ## Function ptr's are retrieved by PEB walk. Will fail if module is not loaded into process.
    let funcNameStr = funcName.strVal
    quote do:
        var `funcName`* {.inject.} = cast[`funcDef`](hashAsciiStatic(`libName`).getProcAddressByHash(hashAsciiStatic(`funcNameStr`)))

proc getModuleHandleByHash*(modHash: string): PVOID =
    ## Given a hash of a module name, returns the module base.
    let peb: PEB = cast[PPEB](GetPEB())[]
    let head: NIMJA_LDR_DATA_TABLE_ENTRY = cast[ptr NIMJA_LDR_DATA_TABLE_ENTRY](cast[LIST_ENTRY](cast[ptr PEB_LDR_DATA](peb.Ldr)[].Reserved2[1]).Flink)[]
    let tail = head.InLoadOrderLinks.Blink
    var cursor = head
    var done = false
    while not done: # iterate through InLoadOrderLinks until we find our dll base address
        if cast[uint](cursor) == cast[uint](tail): done = true # reached end of list
        if(cursor.BaseDllName.ustringToAscii().hashAscii() == modHash): # module found
            done = true
            return cursor.DllBase
        if not done:
            cursor = cast[ptr NIMJA_LDR_DATA_TABLE_ENTRY](cursor.InLoadOrderLinks.Flink)[]

    return cast[PVOID](0) # module not found, not loaded?

proc getProcAddressByHash*(modHash, funcHash: string): FARPROC =
    ## Given a hash of a module name and a hash of a function name exported by that module, returns the address of the function.
    
    # First get the module base address
    var modBase: PVOID = getModuleHandleByHash(modHash)
    if modBase == NULL:
        return NULL # module not loaded

    # Now we get the exported function address
    var
        dosHeader: IMAGE_DOS_HEADER
        ntHeader: IMAGE_NT_HEADERS
        exportDirectory: IMAGE_EXPORT_DIRECTORY
        exportDirectoryOffset: DWORD
        pExportFuncTable: SIZE_T
        pExportNameTable: SIZE_T
        pExportOrdinalTable: SIZE_T
        pFunc: PVOID
        ord: WORD
        pName: PCHAR
    
    dosHeader = cast[ptr IMAGE_DOS_HEADER](modBase)[]
    ntHeader = cast[ptr IMAGE_NT_HEADERS](modBase + dosHeader.e_lfanew)[]
    exportDirectoryOffset = (ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress
    exportDirectory = cast[ptr IMAGE_EXPORT_DIRECTORY](modBase + exportDirectoryOffset)[]

    pExportFuncTable = cast[SIZE_T](modBase) + exportDirectory.AddressOfFunctions
    pExportNameTable = cast[SIZE_T](modBase) + exportDirectory.AddressOfNames
    pExportOrdinalTable = cast[SIZE_T](modBase) + exportDirectory.AddressOfNameOrdinals 

    for funcNum in 0 .. exportDirectory.NumberOfNames:
        var funcName: string

        pName = cast[PCHAR](modBase + cast[ptr DWORD](pExportNameTable + funcNum * sizeof(DWORD))[])
        ord = cast[ptr WORD](pExportOrdinalTable + funcNum * sizeof(WORD))[]
        pFunc = cast[PVOID](modBase + cast[ptr DWORD](pExportFuncTable + ord.int * sizeof(DWORD))[])

        funcName = pCharToString(pName)
        if funcHash == hashAscii(funcName):
            if cast[PVOID](modBase + exportDirectoryOffset) <= pFunc and pFunc < (modBase + exportDirectoryOffset + (ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size):
                # forwarded import
                var fwdStr = pCharToString(cast[PCHAR](pFunc)).rsplit(".", 1)
                return getProcAddressByHash(hashAscii((fwdStr[0] & ".dll")), hashAscii(fwdStr[1]))
            else:
                return cast[FARPROC](pFunc)

    return NULL