def lines2num(lines,nums):
    for l in lines:
        buf = l.split('\t')
        buf = buf[1:]
        for b in buf:
            b = b.strip()
            nums.append(b)


f = open('gdb.txt','r')
lines = f.readlines()
num = []
lines2num(lines,num)
num.sort()
for i in range(len(num)):
    n = num[i]
    if n == '0x08048580':
        print i
print 'Done'

