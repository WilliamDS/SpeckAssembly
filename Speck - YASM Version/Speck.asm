GLOBAL _DllMainCRTStartup
;   EXPORT _DllMainCRTStartup
GLOBAL DllMain
;   EXPORT DllMain
GLOBAL SpeckEncrypt
   EXPORT SpeckEncrypt
GLOBAL SpeckDecrypt
   EXPORT SpeckDecrypt

section .code

..start:

DllMain:		; This code is required in .dll files 
        mov rax,1
        ret

_DllMainCRTStartup:		; This code is required in .dll files 
        mov rax,1
        ret


SpeckEncrypt:
; Pass in 3 addresses pointing to the base of the plainText, cipherText, and Key arrays
; These come in as RCX, RDX, and R8, respectively
; I will use These, RAX, and R9 through R15 for my working space.  Will do 128 bit block, 128 bit key sizes, but they will fit nicely in 64 bit registers

; simple prologue, pushing ebp and ebx and the R# registers, and moving the value of esp into ebp for the duration of the proc  
push rbp
mov rbp,rsp
push rbx
push R9
push R10
push R11
push R12
push R13
push R14
push R15
  
; Move data into the registers for processing
mov r9,[rcx] ; rcx holds the memory location of the first 64 bits of plainText.  Move this into R9.  This is plainText[0] 
mov r10,[rcx+8] ; put next 64 bits into R10.  This is plainText[1]
;NOTE that the address of the cipherText is in RDX but we will fill r11 and r12 with values pointed at by RCX.  This is per the algorithm.  We will use RDX to output the final bytes
mov r11,[rcx] ; cipherText[0] = plainText[0]
mov r12,[rcx+8] ; cipherText[1] = plainText[1] 
mov r13, [r8] ;First 64 bits of key.  This is Key[0]
mov r14, [r8+8] ; Next 64 bits of key.  This is Key[1]

push rcx ; I could get away without this and loop in another register, but I want to count my loop in rcx so I free it up for that
mov rcx, 0 ; going to count up from here to 32.  Would count down but the algorithm uses the counter value in one permutation, so going to count up

EncryptRoundFunction:
ror r12,8
add r12,r11
xor r12,r13
rol r11,3
xor r11,r12

ror r14,8
add r14,r13
xor r14,rcx
rol r13,3
xor r13,r14

inc rcx
cmp rcx, 32
jne EncryptRoundFunction

pop rcx
; Move cipherText into memory pointed at by RDX.  We won't bother copying the Key or plainText back out
mov [rdx],r11
mov [rdx+8],r12
       
; Now the epilogue, returning values from the stack into non-volatile registers.
pop R15
pop R14
pop R13
pop R12
pop R11
pop R10
pop R9    
pop rbx    
pop rbp
ret ; return rax


SpeckDecrypt:
; Pass in 3 addresses pointing to the base of the cipherText, plainText, and Key arrays
; These come in as RCX, RDX, and R8, respectively
; I will use These, RAX, and R9 through R15 for my working space.  Will do 128 bit block, 128 bit key sizes, but they will fit nicely in 64 bit registers

; simple prologue, pushing ebp and ebx and the R# registers, and moving the value of esp into ebp for the duration of the proc  
push rbp
mov rbp,rsp
push rbx
push R9
push R10
push R11
push R12
push R13
push R14
push R15
  
; Move data into the registers for processing
mov r9,[rcx] ; rcx holds the memory location of the first 64 bits of cipherText.  Move this into R9.  This is cipherText[0] 
mov r10,[rcx+8] ; put next 64 bits into R10.  This is cipherText[1]
;NOTE that the address of the plainText is in RDX but we will fill r11 and r12 with values pointed at by RCX.  This is per the algorithm.  We will use RDX to output the final bytes
mov r11,[rcx] ; plainText[0] = cipherText[0]
mov r12,[rcx+8] ; plainText[1] = cipherText[1] 
mov r13, [r8] ;First 64 bits of key.  This is Key[0]
mov r14, [r8+8] ; Next 64 bits of key.  This is Key[1]

push rcx ; I could get away without this and loop in another register, but I want to count my loop in rcx so I free it up for that
mov rcx, 0 ; We will count up while making the round keys

DecryptMakeRoundKeys:
; On encrypt we could make each key just as we needed it.  But here we need the keys in reverse order.  To undo round 31 of encryption, for example, we need round key 31.
; So we will make them all and push them on the stack, pop them off again as we need them in the main DecryptRoundFunction
; I should pull this off and call it for encrypt and decrypt to save space, but for now will have it separate

; push r13 at the beginning of the process because we need a "raw" key by the time we reach decrypt round 0
; We will not push r14 because that half of the key is only used here in the round key generation function.
; We don't need it in the decrypt rounds
push r13

ror r14,8
add r14,r13
xor r14,rcx
rol r13,3
xor r13,r14

inc rcx
cmp rcx, 32
jne DecryptMakeRoundKeys

mov rcx, 32
DecryptRoundFunction:
dec rcx
pop r13

xor r11,r12
ror r11,3
xor r12,r13
sub r12,r11
rol r12,8

cmp rcx, 0
jne DecryptRoundFunction


pop rcx
; Move cipherText into memory pointed at by RDX.  We won't bother copying the Key or plainText back out
mov [rdx],r11
mov [rdx+8],r12
       
; Now the epilogue, returning values from the stack into non-volatile registers.
pop R15
pop R14
pop R13
pop R12
pop R11
pop R10
pop R9    
pop rbx    
pop rbp
ret; return edx