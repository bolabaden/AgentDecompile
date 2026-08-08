# Real capture: rep/repe-prefixed string operations
# Source: objdiff-cli disassembly of
#   0x578fa0_sub_178fa0_packaged-source_packaged-source_d4ef8dff34d1/profile_01_O2_Oy_GSminus
#   (candidateAsm, match_percent=58.0) in the swkotor-parity work dir.
# Dialect: objdiff 'instruction.formatted' (Intel syntax, iced-x86).
.globl _sub_178fa0
_sub_178fa0:
    push ecx
    mov eax, [esp]
    push edi
    mov edi, [eax]
    test edi, edi
    je short 0x20
    mov ecx, [eax+0x4]
    and ecx, 0x3fffffff
    je short 0x20
    or eax, 0xffffffff
    rep stosd [edi]
    jmp short 0x20
    lea ecx, [ecx]
    pop edi
    pop ecx
    ret
