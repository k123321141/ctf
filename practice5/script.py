from pwn import *
import sys
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('csie.ctf.tw',10141)
else:
    r = remote('localhost',8888)
#r.interactive()
def allocate(size,data):
    r.sendline('1')
    r.recvuntil('Size')
    r.send(str(size))
    r.recvuntil('Data')
    r.send(data)
def free(idx):
    r.sendline('2')
    r.recvuntil('Index')
    r.sendline(str(idx))

allocate(0x10, 'A'*8)
#allocate(0x10, 'B'*8)
#free(0)
#free(1)

r.interactive()
