#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char buf[20];
int main(){
	//char buf[0x20];
	//setvbuf(stdout,0,_IONBF,0);
    int a = 3;
    int* b = &a;
    int c = 5;
    int d = 6;
    int e = 7;
    int f = 8;
    int g = 9;
    printf("Read your input: %1$p",b,a,c,d,e,f,g);
	//read(0,buf,0x30);
	return 0 ;
}
