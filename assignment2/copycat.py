from pwn import *
import struct
def sign2unsign(i):
    if i < 0:
        i = (2**32 - i)
    return i
def overflow(i,byte_len = 4):
    i = i % 2**(byte_len*8)
    return i
    

s = raw_input('')
str_len = len(s)

f = open('./flag','wb')

for i in range(str_len):
    j = i+1
    k = i+2

    a = 0xcccccccd
    buf1 = a * k
    d = int(buf1/ 0x100000000)
    d = d / 8
    a = d + d*4
    d = j
    a = a+a
    k = k-a
    k = sign2unsign(k)
    buf = s[i:i+1]
    buf = ord(buf)
    cl = k % 0x100
    d = d << cl
    buf = buf * d
    buf = buf + 0x2333
    buf = overflow(buf)
    f.write(struct.pack('<I',buf))
f.close()
