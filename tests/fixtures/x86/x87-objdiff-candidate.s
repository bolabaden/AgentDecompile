# Real capture: x87 FPU stack operands (st, st(0), qword ptr [__real@...])
# Source: objdiff-cli disassembly of
#   0x4a9770_sub_a9770_packaged-source_packaged-source_c23217925789/profile_01_O2_Oy_GSminus
#   (candidateAsm, match_percent=90.0) in the swkotor-parity work dir.
# Dialect: objdiff 'instruction.formatted' (Intel syntax, iced-x86).
.globl _sub_a9770
_sub_a9770:
    mov eax, [esp+0x4]
    mov ecx, [esp+0x4]
    fld st, dword ptr [eax]
    fsub st, dword ptr [ecx]
    fstp dword ptr [eax], st
    fld st, dword ptr [eax+0x4]
    fsub st, dword ptr [ecx+0x4]
    fstp dword ptr [eax+0x4], st
    fld st, dword ptr [eax+0x8]
    fsub st, dword ptr [ecx+0x8]
    fstp dword ptr [eax+0x8], st
    ret
