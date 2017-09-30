def out(s):
    f = open('out','wb')
    f.write(s)
    f.close()

def r():
    str = ''
    with open('in','r') as f:
        str = f.read()
    return str

def binstr2hex(s):
    l = len(s)
    result = 0
    for i in range(l):
        b = ord(s[i:i+1])
        shift_offset = i*8
        result += (b << shift_offset )
    return result
