# Real capture: switch jump table indexed through a $LN compiler-local label
# Source: objdiff-cli disassembly of
#   0x408c00_sub_8c00_packaged-source_packaged-source_86048255e62d/profile_01_O2_Oy_GSminus
#   (candidateAsm, match_percent=50.242424) in the swkotor-parity work dir.
# Dialect: objdiff 'instruction.formatted' (Intel syntax, iced-x86).
.globl _sub_8c00
_sub_8c00:
    mov eax, [esp+0xc]
    add eax, 0xffffffff
    cmp eax, 0x3
    ja short 0x59
    jmp dword ptr [eax*0x4+$LN11]
    mov eax, [esp+0xc]
    add eax, 0x10
    jmp short 0x35
    mov eax, [esp+0xc]
    add eax, 0x14
    jmp short 0x35
    mov eax, [esp+0xc]
    add eax, 0x18
    jmp short 0x35
    mov eax, [esp+0xc]
    add eax, 0x1c
    test eax, eax
    je short 0x59
    push 0x0
    lea ecx, [esp+0x10]
    push ecx
    mov ecx, [esp+0x10]
    lea edx, [esp+0x10]
    push edx
    mov edx, [esp+0x10]
    push ecx
    push edx
    push eax
    call _sub_71a0
    add esp, 0x18
    ret
    xor eax, eax
    ret
