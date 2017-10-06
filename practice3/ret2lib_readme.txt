binary檔案是沒有開啟PIE 但是有ASLR
而外部函式庫是Partial RELRO

透過ret2lib方式 可以執行system('/bin/sh')
找到一個gadget是pop rdi就可以指定system function的參數
而字串'/bin/sh'也可以在libc.so.6中找到 str_sh
一樣透過gets overflow蓋過ret addr

libc.so.6 offset資訊如下:
'/bin/sh'		0x18cd17
system			0x045390

ret2lin gadget offset:

'pop rdi;ret'		0x400823

完整輸入流程請見runme_ret2lib.py

ELF資訊:
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)


