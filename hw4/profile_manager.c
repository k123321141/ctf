#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#define TIMEOUT 60
struct profile{
	bool is_valid ;
	unsigned int age ;
	char *name ;
	char *desc ;
};

struct profile p[5] ;

void handler(int signum){
    puts("Timeout");
    _exit(1);
}
void init_proc(){
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
    signal(SIGALRM,handler);
    alarm(TIMEOUT);
}


int read_int(){
	int ret ;
    char buf[16];
    unsigned choice ;
    ret = __read_chk(0,buf,15,15);
    if(ret <= 0){
        puts("read error");
        exit(1);
    }
    choice = atoi(buf);
    return choice;
} 	

void menu(){
	puts("===================================");
	puts("          Profile Manager          ");	
	puts("===================================");
	puts(" 1. Add a profile                  ");
	puts(" 2. Show a profile                 ");
	puts(" 3. Edit a profile                 ");
	puts(" 4. Delete a profile               ");
	puts(" 5. Exit                           ");
	puts("===================================");
	printf("Your choice :");

}

void add_profile(){
	char buf[0x20];
	char *tmp = NULL;
	size_t size ;
	memset(buf,0,0x20);
	for(int i = 0 ; i < 5 ; i++){
		if(!p[i].is_valid){
			printf("Name :");
			read(0,buf,16);
            
            #傳回一塊malloc出來的空間 並且將buf內容copy到該空間 使用者要自己free新建的空間
			#漏洞 會有之前殘留值 可以做info leak
            p[i].name = strdup(buf);
			printf("Age :");
            #輸入非數字最後會變成0
			p[i].age = read_int();
			printf("Length of description :");
			size = read_int();
            #not fast bin
			if(size < 0x90){
				puts("Length must be larger than 0x90");
				free(p[i].name);
				return ;
			}
			printf("Description :");
            #配置1個大小為size的空間
            #漏洞 可以輸入-1導致跳出 而name及age已經被設置
			tmp = calloc(1,size);
			if(!tmp){
				puts("Allocate Error !");
				return ;
			}
			p[i].desc = tmp ;
			read(0,p[i].desc,size-1);
			p[i].is_valid = true;
			puts("Done !");
			return ;
		}
	}
	puts("Fulled !");
}

void show_profile(){
	unsigned int idx ;
	printf("ID :");
	idx = read_int();
	if(idx >= 5){
		puts("Out of bound !");
		_exit(0);
	}
	if(p[idx].is_valid){
		printf("= Name : %s\n",p[idx].name);
		printf("= Age : %u\n",p[idx].age);
		printf("= Desc : %s\n",p[idx].desc);
	}else{
		puts("No such profile !");
	}
}

void edit_profile(){
	unsigned int idx ;
	char *tmp = NULL ;
	char buf[0x20];
	memset(buf,0,0x20);
	printf("ID :");
	idx = read_int();
	if(idx >= 5){
		puts("Out of bound !");
		_exit(0);
	}
	if(p[idx].is_valid){
		printf("Name :");
		read(0,buf,16);
        #if the src address is smaller than new length
        #free the old variable,then malloc a new address to tmp
        #漏洞 realloc(ptr,0) 會被當成 free(ptr) 傳'\x00'*16過去
        #之後就會有free after use
		tmp = realloc(p[idx].name,strlen(buf));
		if(!tmp){
			puts("Realloc Error !");
			return ;
		}
		p[idx].name = tmp;
        #漏洞 copy len(buf) buf到name 沒有補上0 結尾字元
        #沒用 buf最長buf 不管怎樣都是malloc 0x20
		strncpy(p[idx].name,buf,strlen(buf));
		tmp = NULL ;
		printf("Age :");
		p[idx].age = read_int();
		printf("Description :");
        #讀入比之前的desc等長或更短的字串
        #漏洞 透過接上之前的malloc出來的殘留值 就可以填超過chunk做overflow 只可以更改prev size
		read(0,p[idx].desc,strlen(p[idx].desc));
		puts("Done !");
	}else{
		puts("No such profile !");
	}

}

void del_profile(){
	unsigned int idx ;
	printf("ID :");
	idx = read_int();
	if(idx >= 5){
		puts("Out of bound !");
		_exit(0);
	}
	if(p[idx].is_valid){
		p[idx].is_valid = false;
		free(p[idx].name);
		p[idx].name = NULL;
		free(p[idx].desc);
		p[idx].desc = NULL;

		p[idx].age = 0 ;
		puts("Done !");
	}else{
		puts("No such profile !");
	}
}

int main(){
	init_proc();
	while(1){
		menu();
		switch(read_int()){
			case 1 :
				add_profile();
				break ;
			case 2 :
				show_profile();
				break ;
			case 3 :
				edit_profile();
				break ;
			case 4 :
				del_profile();
				break ;
			case 5 :
				_exit(0);
				break ;
			default :
				puts("Invalid choice");
				break ;

		}
	}
}
