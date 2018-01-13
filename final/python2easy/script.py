from pwn import *

r = remote('35.201.132.60',12000)


#read file
def rf(name):
    r.sendline('0')
    r.recvuntil('input filename :')
    r.sendline(name)
    reply = r.recvline()
    return reply
#write f    
def wf(name, data):
    r.sendline('1')
    r.recvuntil('input filename :')
    r.sendline(name)
    r.recvuntil('input input data in hex :')
    r.sendline(data)
#check key
def ck(key):
    r.sendline('2')
    r.recvuntil('input secret key :')
    r.sendline(key)
    r.recvuntil('The old key is ')
    old_key = r.recvline().strip()
    #print old_key
def ck_en():
    en_path = '/proc/sys/kernel/random/entropy_avail'
    count = rf(en_path).replace('a','')
    count = int(count)
    print count
def test():
    pyc = rf('secret.pyc')
    #pyc = pyc.decode('hex')
    print pyc
#send name
r.recvuntil('Name')
r.sendline('Payo')
#rf('/dev/urandom')
for i in range(10):
    ck_en()
    test()
    for _ in range(10):
        ck('123')
r.interactive()
