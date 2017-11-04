#include <stdio.h>
#include <stdlib.h>

int foo()
{
    int k = 3;
}
int main(){
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);

	char *smallbin_chunk ;
	char *largebin_chunk ;
	char *temp ;
	smallbin_chunk = (char *)malloc(0x80) ;// small bin chunk
	temp = (char *)malloc(0x10) ;// avoid merge to top
	largebin_chunk = (char *)malloc(0x400); // large bin chunk	
	temp = (char *)malloc(0x10) ;// avoid merge to top


	printf("free a largebin_chunk %p\n",largebin_chunk);
    free(largebin_chunk); 	
	foo();
	free(smallbin_chunk);
    foo();
	printf("free the smallbin_chunk %p and merge with largebin_chunk %p\n",smallbin_chunk,largebin_chunk);
	foo();
	return 0;
}
