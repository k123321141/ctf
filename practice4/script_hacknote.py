from pwn import *
from time import sleep
context.arch = 'amd64'

#r = remote('csie.ctf.tw',10137)
r = remote('localhost',8888)
#r.interactive()
size = '64'
content = 'aaa'

#first two
r.sendline('1')
r.send(size)
r.send(content)
r.interactive()
