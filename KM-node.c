#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h> 
#include <time.h>
#include <sys/wait.h>
#include <stdbool.h> 
#include "aes/aes.h"

#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 
#define CBC_MODE 0
#define OFB_MODE 1
#define K3 "2b7e151628aed2a6abf7158809cf4f3c"
typedef unsigned char       BYTE;
typedef unsigned int        DWORD;


#define SOCKET_TCP_CHECK(descriptor)      					if((descriptor = socket(AF_INET, SOCK_STREAM,0)) == -1){ perror("[KM]: Socket error "); return errno;}
#define BIND_CHECK(descriptor,structure)					if(bind(descriptor,(struct sockaddr *)&structure, sizeof(struct sockaddr))==-1){  perror("[SERVER] Bind error "); return errno; }
#define LISTEN_CHECK(descriptor)                   			if(listen(descriptor,1)==-1){ perror("[KM]: Listen error "); return errno;}
#define ACCEPT_CHECK(client,descriptor,structure,length)    client= accept(descriptor,(struct sockaddr *)&structure,&length); if(client<0){perror("[SERVER] Fork error "); continue; }

#define READ_CHECK(from,in,size)                   			if(read(from,in,size)<0){perror("[KM]: Read error "); return errno;}
#define WRITE_CHECK(from,in,size)                   		if(write(from,in,size)<0){perror("[KM]: Write error "); return errno;}

BYTE K1[AES_BLOCKLEN],K2[AES_BLOCKLEN];
BYTE randomByte(){
    double scale=1.0/(RAND_MAX+1);
    double range= 255 - 0 +1;
    int randomByte= 0 + (int) ( rand() * scale * range);
    return (BYTE) randomByte;
}
void generateK1(){
    for(int i=0;i<AES_BLOCKLEN;i++){
        K1[i]=randomByte();
    }
    K1[AES_BLOCKLEN]='\0';
}
void generateK2(){
    for(int i=0;i<AES_BLOCKLEN;i++){
        K2[i]=randomByte();
    }
    K2[AES_BLOCKLEN]='\0';
}

int main(){
    int sockfd, connfd, len; 
    struct sockaddr_in servaddr, from; 
  
    SOCKET_TCP_CHECK(sockfd)
    perror("[KM]: CREATE SOCKET");
    
    bzero(&servaddr, sizeof(servaddr)); 
    bzero (&from, sizeof (from));

    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
    
    BIND_CHECK(sockfd,servaddr);
    perror("[KM]: BIND");
  
    LISTEN_CHECK(sockfd);
    perror("[KM]: LISTEN");

     while (1)
    {
    	int client;
    	socklen_t length = sizeof (from);

		ACCEPT_CHECK(client,sockfd,from,length);
		perror("[KM]: ACCEPT");			
	

        // 0 or 1 , 0 for CBC and 1 for OFB
        int cryptoMode;
        READ_CHECK(client,&cryptoMode,sizeof(int));


        if(cryptoMode==CBC_MODE){
            generateK1();
            struct AES_ctx ctx;
            BYTE buff[sizeof(K1)];
            strcpy(buff,K1);

            AES_init_ctx(&ctx, K3);
            AES_ECB_encrypt(&ctx, buff);

            DWORD size=sizeof(buff);
            WRITE_CHECK(client,&size,sizeof(DWORD));

            WRITE_CHECK(client,buff,size);
        }
        else{
            generateK2();
            struct AES_ctx ctx;
            BYTE buff[sizeof(K2)];
            strcpy(buff,K2);

            AES_init_ctx(&ctx, K3);
            AES_ECB_encrypt(&ctx, buff);

            DWORD size=sizeof(buff);
            WRITE_CHECK(client,&size,sizeof(DWORD));

            WRITE_CHECK(client,buff,size);
        }

    }
    
}