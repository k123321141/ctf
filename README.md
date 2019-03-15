# NTU 計算機安全 2017 spring的作業筆記
各題解法寫在小題的readme裡面</br>
 
## 流程
 file path-to-file</br> 
 檢查binary code, 32/64 bits</br>

## trace
strace, trace system call</br>
ltrace, trace library call</br>

## 修改binary
vim -b ,--binary</br>
開啟vim 後 使用:%!xxd進入16進位顯示模式</br>
可以直接改binary file</br>
改完後使用:%!xxd -r 改回預設顯示模式 存檔</br>

## 防禦機制專有名詞

ASLR</br>
address Space Layout Reandomization</br></br>

PIE</br>
position independent executables</br></br>

Stack Canaries</br></br>

