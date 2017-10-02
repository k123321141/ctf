from pwn import *
import struct as st
def s2us(i):
    return i if i >=0 else (2**32 - i)

with open('./flag','rb') as f:
    s = f.read()
str_len = len(s)
i=0
result = ''
while i < (str_len/4):
    data = s[i*4: (i+1)*4]
    buf = st.unpack('<I',data)[0]
    #print 'src ',hex(buf)
    buf = buf - 0x2333
    #
    j = i+1
    k = i+2
    a = 0xcccccccd
    buf1 = a*k
    d = int(buf1/ 0x100000000)
    d = d / 8
    a = d + d*4
    d = j
    a = a+a
    k = k-a
    k = s2us(k)
    cl = k % 0x100
    d = d << cl
    #
    buf = 0 if d == 0 else buf / d

    result += chr(buf)
    i += 1
print result


