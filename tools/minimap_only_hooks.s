.intel_syntax noprefix
.code32
.section .text

/* Runtime sentinels:
   0x11111111 logical width u16
   0x22222222 logical height u16
   0x33333333 parser active byte
   0x44444444 unit width table
   0x44444446 unit height table
   0x55555555 camera rectangle color
   0x66666666 scroll X pixels dword
   0x77777777 scroll Y pixels dword
   0xAAAAAAAA draw filled rectangle
   0xBBBBBBBB draw outline rectangle
   0xEEEEEEEE stock minimap shift global
*/

.macro RECT_GUARD fallback
    cmp byte ptr [0x33333333], 0
    je \fallback
    cmp byte ptr [0xA5A5A5A5], 0
    je \fallback
    movzx eax, word ptr [0x11111111]
    cmp ax, word ptr [0x22222222]
    je \fallback
.endm

.global dot_hook
.type dot_hook,@function
dot_hook:
    RECT_GUARD dot_fallback

    /* X: map tile -> full 128-pixel minimap. */
    movsx eax, word ptr [esi+0x18]
    test eax, eax
    jns 1f
    xor eax, eax
1:  imul eax, eax, 128
    cdq
    movzx ecx, word ptr [0x11111111]
    idiv ecx
    add eax, 24
    cmp eax, 24
    jge 2f
    mov eax, 24
2:  cmp eax, 151
    jle 3f
    mov eax, 151
3:  mov dword ptr [ebp-8], eax

    /* Y: map tile -> full 128-pixel minimap. */
    movsx eax, word ptr [esi+0x1a]
    test eax, eax
    jns 4f
    xor eax, eax
4:  imul eax, eax, 128
    cdq
    movzx ecx, word ptr [0x22222222]
    idiv ecx
    add eax, 2
    cmp eax, 2
    jge 5f
    mov eax, 2
5:  cmp eax, 129
    jle 6f
    mov eax, 129
6:  mov dword ptr [ebp-0xc], eax

    /* Keep markers compact using a uniform scale based on the larger axis. */
    movzx ebx, byte ptr [esi+0x27]
    movzx eax, word ptr [ebx*4+0x44444444]
    imul eax, eax, 128
    movzx ecx, word ptr [0x11111111]
    movzx edx, word ptr [0x22222222]
    cmp ecx, edx
    cmovb ecx, edx
    add eax, ecx
    dec eax
    xor edx, edx
    div ecx
    cmp eax, 2
    jae 7f
    mov eax, 2
7:  cmp eax, 6
    jbe 8f
    mov eax, 6
8:  mov ecx, 152
    sub ecx, dword ptr [ebp-8]
    cmp eax, ecx
    jle 9f
    mov eax, ecx
9:  cmp eax, 1
    jge 10f
    mov eax, 1
10: mov dword ptr [ebp-4], eax

    movzx eax, word ptr [ebx*4+0x44444446]
    imul eax, eax, 128
    movzx ecx, word ptr [0x11111111]
    movzx edx, word ptr [0x22222222]
    cmp ecx, edx
    cmovb ecx, edx
    add eax, ecx
    dec eax
    xor edx, edx
    div ecx
    cmp eax, 2
    jae 11f
    mov eax, 2
11: cmp eax, 6
    jbe 12f
    mov eax, 6
12: mov ecx, 130
    sub ecx, dword ptr [ebp-0xc]
    cmp eax, ecx
    jle 13f
    mov eax, ecx
13: cmp eax, 1
    jge 14f
    mov eax, 1
14: mov dword ptr [ebp-0x10], eax

    movzx eax, byte ptr [ebp+0xb]
    push eax
    push dword ptr [ebp-0x10]
    push dword ptr [ebp-4]
    push dword ptr [ebp-0xc]
    push dword ptr [ebp-8]
    mov eax, 0xAAAAAAAA
    call eax
    add esp, 20
    pop edi
    pop esi
    pop ebx
    mov esp, ebp
    pop ebp
    ret

dot_fallback:
    movzx ecx, word ptr [0xEEEEEEEE]
    push 0xEFEFEFEF
    ret
.size dot_hook,.-dot_hook

.global click_hook
.type click_hook,@function
click_hook:
    RECT_GUARD click_fallback

    mov eax, dword ptr [esp+4]
    movsx ecx, word ptr [eax]
    sub ecx, 24
    jns 20f
    xor ecx, ecx
20: cmp ecx, 127
    jle 21f
    mov ecx, 127
21: mov eax, ecx
    imul eax, 128
    movzx edx, word ptr [0x11111111]
    imul eax, edx
    shr eax, 14
    cmp eax, edx
    jb 22f
    dec edx
    mov eax, edx
22: mov edx, dword ptr [esp+4]
    mov word ptr [edx], ax

    mov eax, dword ptr [esp+8]
    movsx ecx, word ptr [eax]
    sub ecx, 26
    jns 23f
    xor ecx, ecx
23: cmp ecx, 127
    jle 24f
    mov ecx, 127
24: mov eax, ecx
    imul eax, 128
    movzx edx, word ptr [0x22222222]
    imul eax, edx
    shr eax, 14
    cmp eax, edx
    jb 25f
    dec edx
    mov eax, edx
25: mov edx, dword ptr [esp+8]
    mov word ptr [edx], ax
    ret

click_fallback:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push 0xF0F0F0F0
    ret
.size click_hook,.-click_hook

.global camera_hook
.type camera_hook,@function
camera_hook:
    RECT_GUARD camera_fallback
    pop ebx
    movzx eax, byte ptr [0x55555555]
    push eax

    /* Rectangle height in minimap pixels. Viewport globals here are pixels. */
    movzx eax, word ptr [0xC2C2C2C2]
    imul eax, eax, 4
    movzx ecx, word ptr [0x22222222]
    add eax, ecx
    dec eax
    xor edx, edx
    div ecx
    cmp eax, 1
    jae 30f
    mov eax, 1
30: cmp eax, 128
    jbe 31f
    mov eax, 128
31: push eax

    movzx eax, word ptr [0xC1C1C1C1]
    imul eax, eax, 4
    movzx ecx, word ptr [0x11111111]
    add eax, ecx
    dec eax
    xor edx, edx
    div ecx
    cmp eax, 1
    jae 32f
    mov eax, 1
32: cmp eax, 128
    jbe 33f
    mov eax, 128
33: push eax

    mov eax, dword ptr [0x77777777]
    test eax, eax
    jns 34f
    xor eax, eax
34: imul eax, eax, 4
    xor edx, edx
    movzx ecx, word ptr [0x22222222]
    div ecx
    cmp eax, 127
    jbe 35f
    mov eax, 127
35: push eax

    mov eax, dword ptr [0x66666666]
    test eax, eax
    jns 36f
    xor eax, eax
36: imul eax, eax, 4
    xor edx, edx
    movzx ecx, word ptr [0x11111111]
    div ecx
    cmp eax, 127
    jbe 37f
    mov eax, 127
37: push eax

    mov eax, 0xBBBBBBBB
    call eax
    add esp, 20
    pop edi
    pop esi
    ret

camera_fallback:
    movzx eax, byte ptr [0x55555555]
    push 0xF1F1F1F1
    ret
.size camera_hook,.-camera_hook


/* Scoped pointer swaps: only the two classic minimap raster functions see the
   resampled buffers. World rendering keeps the original 0.9.0 pointers/side. */
.global fog_entry
.type fog_entry,@function
fog_entry:
    cmp byte ptr [0xA5A5A5A5], 0
    je fog_trampoline
    pop eax
    mov dword ptr [0xA6A6A6A6], eax
    pushad
    mov eax, dword ptr [0x90909090]
    mov dword ptr [0xB1B1B1B1], eax
    mov eax, dword ptr [0x94949494]
    mov dword ptr [0xB2B2B2B2], eax
    mov eax, dword ptr [0x98989898]
    mov dword ptr [0xB3B3B3B3], eax
    movzx eax, word ptr [0x9C9C9C9C]
    mov word ptr [0xB4B4B4B4], ax
    mov eax, dword ptr [0xA1A1A1A1]
    mov dword ptr [0x90909090], eax
    mov eax, dword ptr [0xA2A2A2A2]
    mov dword ptr [0x94949494], eax
    mov eax, dword ptr [0xA3A3A3A3]
    mov dword ptr [0x98989898], eax
    movzx eax, word ptr [0xA4A4A4A4]
    mov word ptr [0x9C9C9C9C], ax
    popad
    push 0xD1D1D1D1
fog_trampoline:
    push ebp
    mov ebp, esp
    push -1
    push 0xD2D2D2D2
    ret
.size fog_entry,.-fog_entry

.global fog_restore
.type fog_restore,@function
fog_restore:
    pushad
    mov eax, dword ptr [0xB1B1B1B1]
    mov dword ptr [0x90909090], eax
    mov eax, dword ptr [0xB2B2B2B2]
    mov dword ptr [0x94949494], eax
    mov eax, dword ptr [0xB3B3B3B3]
    mov dword ptr [0x98989898], eax
    movzx eax, word ptr [0xB4B4B4B4]
    mov word ptr [0x9C9C9C9C], ax
    popad
    jmp dword ptr [0xA6A6A6A6]
.size fog_restore,.-fog_restore

.global terrain_entry
.type terrain_entry,@function
terrain_entry:
    cmp byte ptr [0xA5A5A5A5], 0
    je terrain_trampoline
    pop eax
    mov dword ptr [0xA7A7A7A7], eax
    pushad
    mov eax, dword ptr [0x90909090]
    mov dword ptr [0xC5C5C5C5], eax
    mov eax, dword ptr [0x94949494]
    mov dword ptr [0xC6C6C6C6], eax
    mov eax, dword ptr [0x98989898]
    mov dword ptr [0xC7C7C7C7], eax
    movzx eax, word ptr [0x9C9C9C9C]
    mov word ptr [0xC8C8C8C8], ax
    mov eax, dword ptr [0xA1A1A1A1]
    mov dword ptr [0x90909090], eax
    mov eax, dword ptr [0xA2A2A2A2]
    mov dword ptr [0x94949494], eax
    mov eax, dword ptr [0xA3A3A3A3]
    mov dword ptr [0x98989898], eax
    movzx eax, word ptr [0xA4A4A4A4]
    mov word ptr [0x9C9C9C9C], ax
    popad
    push 0xD3D3D3D3
terrain_trampoline:
    push ebp
    mov ebp, esp
    push ecx
    mov dx, word ptr [0x9C9C9C9C]
    push 0xD4D4D4D4
    ret
.size terrain_entry,.-terrain_entry

.global terrain_restore
.type terrain_restore,@function
terrain_restore:
    pushad
    mov eax, dword ptr [0xC5C5C5C5]
    mov dword ptr [0x90909090], eax
    mov eax, dword ptr [0xC6C6C6C6]
    mov dword ptr [0x94949494], eax
    mov eax, dword ptr [0xC7C7C7C7]
    mov dword ptr [0x98989898], eax
    movzx eax, word ptr [0xC8C8C8C8]
    mov word ptr [0x9C9C9C9C], ax
    popad
    jmp dword ptr [0xA7A7A7A7]
.size terrain_restore,.-terrain_restore

.global marker
marker:
.ascii "W2EMMINI3"
.balign 4
.global state
state:
.space 64, 0
