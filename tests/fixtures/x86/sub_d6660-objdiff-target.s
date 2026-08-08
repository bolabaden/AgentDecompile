# Real capture: sub_d6660 @ 0x4d6660 -- three-branch free() teardown, target side (no relocations)
# Source: objdiff-cli disassembly of
#   0x4d6660_sub_d6660_packaged-source_packaged-source_ad3ae1b0a761/profile_01_O2_Oy_GSminus
#   (targetAsm, match_percent=90.56) in the swkotor-parity work dir.
# Dialect: objdiff 'instruction.formatted' (Intel syntax, iced-x86).
.globl _sub_d6660
_sub_d6660:
    push esi
    mov esi, ecx
    mov eax, [esi+0x4]
    test eax, eax
    mov dword ptr [esi], 0x7465a4
    je short 0x20
    push eax
    call 0x223d30
    add esp, 0x4
    mov dword ptr [esi+0x4], 0x0
    mov eax, [esi+0x10]
    test eax, eax
    je short 0x37
    push eax
    call 0x223d30
    add esp, 0x4
    mov dword ptr [esi+0x10], 0x0
    test byte ptr [esp+0x8], 0x1
    je short 0x47
    push esi
    call 0x223d30
    add esp, 0x4
    mov eax, esi
    pop esi
    ret 0x4
