程式流程:

接受stdin輸入後
依序每一個byte做加密成4個byte存到./flag檔中

需要拆解組語後，了解加密過程，逆著做回來
過程中有使用sign extension將1 byte放到4 byte register
且使用imul等等指令
考慮到這次加密是可逆函數，所以中間運算不考慮數值overflow問題
其中組語可以轉譯如下python code

檔案說明:

實作逆轉換 -> rev.py
嘗試使用python模擬轉換 -> copycat.py

以下為作業過程的分析

---symbol代換--------

i:ebx
j:esi
k:ecx
a - >eax
d - >edx

---assembly解析------
for i in range(len)
	j = i+1
	k = i+2
	
	a = (0xcccccccd) // unsigned = 0xcccccccd
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
-----------
