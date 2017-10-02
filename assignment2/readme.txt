char buf[64] = '\0'
sacnf('%60s')

open('flag','wb')

movsx : move with signed extension

in encrypt eax = char len


858993459
i:ebx
j:esi
k:ecx

int a:eax
int d:edx
for i in range(len)
	j = i+1
	k = i+2
	
	a = (0xcccccccd) // sign = -858993459
	buf = a*k
	a = low32(buf)
	d = high32(buf)
	d = int(d/8)
	a = d + d*4
	d = j
	a = a+a
	k = k - a
	//eax = &str
	buf = str[i:i+1] //is char,1 byte,movsx,eax ,BYTE PTR [eax+ebx*1]  
	i = j
	cl = low8(k)
	d << cl
	buf = buf * d // imul eax,edx
	int x = buf + 0x2333
	mov dw esp+0xc,eax
