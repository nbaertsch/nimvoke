## File: common.nim
## Author: nbaertsch
## 
## Common functions for 'nimvoke' project. `hashAscii` can be changed to whatever hashing method you want.

from winim/lean import UNICODE_STRING, UCHAR, PVOID, PCHAR, CHAR
from checksums/md5 import getMD5 
from strutils import toLowerAscii, replace
from ptr_math import `+`

var pPEB*: ptr PVOID

proc hashAscii*(funcName: string): string =
    ## MD5 hash ignoring case (toLowerAscii)
    getMD5(funcName.toLowerAscii())

proc hashAsciiStatic*(funcName: string): string {.compiletime.} =
    hashAscii(funcName)
    
proc ustringToAscii*(ustring: UNICODE_STRING): string =
    ## Convert a UNICODE_STRING structure to a nim native ascii string
    result = ""
    var arrayUChar = cast[ptr UncheckedArray[UCHAR]](ustring.Buffer)
    for i in 0.uint32..ustring.Length:
        result = result & arrayUChar[i].char
    result = result.replace("\0")

func pCharToString*(pChar: PCHAR): string =
    ## return a nim string from a c string pointer
    result = ""
    var adr = pChar
    while not (adr[] == '\0' or adr[] == '`' or adr[] == '\176'):
        result = result & adr[].char
        adr = cast[PCHAR](cast[PVOID](adr) + sizeof(CHAR))
    return result

# TODO: Add a x86 implementation
when defined amd64:
    {.passC:"-masm=intel".}
    proc GetPEB*(): ptr PVOID {.asmNoStackFrame.} =
        ## Uses inline assembly to get a pointer to the PEB.
        asm """
            push rbx
            xor rdi, rdi
            mul rdi
            mov rbx, rax
            add rdi, 0x20
            mov rbx, qword ptr gs:[rdi+0x40]
            mov rax, rbx
            pop rbx
            ret
        """

when defined i386:
    {.passC:"-masm=intel".}
    proc GetPEB*(): ptr PVOID {.asmNoStackFrame.} =
        ## Uses inline assembly to get a pointer to the PEB
        asm """
            push rbx
            xor rdi, rdi
            mul rdi
            mov rbx, rax
            add rdi, 0x20
            mov eax, fs:[rdi+0x10]
            pop rbx
            ret
        """

pPEB = GetPEB()
