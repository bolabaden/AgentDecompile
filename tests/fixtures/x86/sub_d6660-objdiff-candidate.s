# Real capture: sub_d6660 candidate -- MSVC-compiled and relocated, so call targets are symbolic
# Source: objdiff-cli disassembly of
#   0x4d6660_sub_d6660_packaged-source_packaged-source_ad3ae1b0a761/profile_01_O2_Oy_GSminus
#   (candidateAsm, match_percent=90.56) in the swkotor-parity work dir.
# Dialect: objdiff 'instruction.formatted' (Intel syntax, iced-x86).
.globl _sub_d6660
_sub_d6660:
    push esi
    mov esi, [esp+0x8]
    mov eax, [esi+0x4]
    test eax, eax
    mov dword ptr [esi], _PTR_sub_d6660_007465a4
    je short 0x22
    push eax
    call __free
    add esp, 0x4
    mov dword ptr [esi+0x4], 0x0
    mov eax, [esi+0x10]
    test eax, eax
    je short 0x39
    push eax
    call __free
    add esp, 0x4
    mov dword ptr [esi+0x10], 0x0
    test byte ptr [esp+0x8], 0x1
    je short 0x49
    push esi
    call __free
    add esp, 0x4
    pop esi
    ret
