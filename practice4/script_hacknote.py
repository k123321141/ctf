from pwn import *

context.arch = 'amd64'

#r = remote('csie.ctf.tw',10137)
r = remote('localhst',8888)
#r.interactive()
size = '64'
content = 'faceb00c'

#first two
r.send('1')
r.send(size)
r.send(content)

r.send('1')
r.send(size)
r.send(content)
#
r.interactive()
