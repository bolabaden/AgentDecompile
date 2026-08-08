# Real capture: MSVC C++ mangled string-literal symbols (?? _C@ ... ?$AA@)
# Source: objdiff-cli disassembly of
#   0x463570_sub_63570_packaged-source_packaged-source_b393284ac5d5/profile_01_O2_Oy_GSminus
#   (candidateAsm, match_percent=99.5) in the swkotor-parity work dir.
# Dialect: objdiff 'instruction.formatted' (Intel syntax, iced-x86).
.globl _sub_63570
_sub_63570:
    mov eax, [esp+0x8]
    lea ecx, [eax+0x8]
    push ecx
    lea edx, [eax+0x4]
    push edx
    push eax
    mov eax, [esp+0x10]
    push ??_C@_08OEKJENGB@?$CFf?5?$CFf?5?$CFf?$AA@
    push eax
    call __sscanf
    add esp, 0x14
    ret
