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
#define PORT 8081
#define KM_PORT 8080

#define CBC_MODE 0
#define OFB_MODE 1
#define K3 "2b7e151628aed2a6abf7158809cf4f3c"
#define Q 10


typedef unsigned char       BYTE;
typedef unsigned int        DWORD;


#define SOCKET_TCP_CHECK(descriptor)      					if((descriptor = socket(AF_INET, SOCK_STREAM,0)) == -1){ perror("[A]: Socket error "); return errno;}
#define BIND_CHECK(descriptor,structure)					if(bind(descriptor,(struct sockaddr *)&structure, sizeof(struct sockaddr))==-1){  perror("[A] Bind error "); return errno; }
#define LISTEN_CHECK(descriptor)                   			if(listen(descriptor,1)==-1){ perror("[A]: Listen error "); return errno;}
#define ACCEPT_CHECK(client,descriptor,structure,length)    client= accept(descriptor,(struct sockaddr *)&structure,&length); if(client<0){perror("[A] Fork error "); return errno; }

#define READ_CHECK(from,in,size)                   			if(read(from,in,size)<0){perror("[A]: Read error "); close(sockfd); return errno;}
#define WRITE_CHECK(from,in,size)                   		if(write(from,in,size)<0){perror("[A]: Write error "); close(sockfd); return errno;}
#define CONNECT_CHECK(descriptor,server)            if( connect(descriptor,(struct sockaddr *) &server,sizeof (struct sockaddr))==-1){perror("[A]: Connect error "); return errno; }

#define FUNCT_CONNECT_CHECK(descriptor,server)            if( connect(descriptor,(struct sockaddr *) &server,sizeof (struct sockaddr))==-1){perror("[A]: Connect error "); return false; }
#define FUNCT_SOCKET_TCP_CHECK(descriptor)      					if((descriptor = socket(AF_INET, SOCK_STREAM,0)) == -1){ perror("[A]: Socket error "); return false;}
#define FUNCT_READ_CHECK(from,in,size)                   			if(read(from,in,size)<0){perror("[A]: Read error "); return false;}
#define FUNCT_WRITE_CHECK(from,in,size)                   		if(write(from,in,size)<0){perror("[A]: Write error "); return false;}
#define FUNCT_CONNECT_CHECK(descriptor,server)            if( connect(descriptor,(struct sockaddr *) &server,sizeof (struct sockaddr))==-1){perror("[A]: Connect error "); return false; }

bool isFirst=true;
BYTE iv[AES_BLOCKLEN],previousIV[AES_BLOCKLEN];

//function that makes a request to KM and retrive a cripted key
//based on the crypto mode selected
bool retriveCryptoMode(char * key,int mode){
    int serverDescriptor;
    struct sockaddr_in server;

    FUNCT_SOCKET_TCP_CHECK(serverDescriptor);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons (KM_PORT);
    FUNCT_CONNECT_CHECK(serverDescriptor,server);

    

    
    FUNCT_WRITE_CHECK(serverDescriptor,&mode,sizeof(int));

    DWORD size;
    FUNCT_READ_CHECK(serverDescriptor,&size,sizeof(DWORD));
    
    FUNCT_READ_CHECK(serverDescriptor,key,size);
    return true;
}
void encrypt_aes(const char* key,BYTE* buff){
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, buff);
    
}
void decrypt_aes(const char* key,BYTE* buff){
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    AES_ECB_decrypt(&ctx, buff);
}

BYTE randomByte(){
    double scale=1.0/(RAND_MAX+1);
    double range= 255 - 0 +1;
    int randomByte= 0 + (int) ( rand() * scale * range);
    return (BYTE) randomByte;
}
void generateIV(){
    for(int i=0;i<AES_BLOCKLEN;i++){
        iv[i]=randomByte();
    }
    iv[AES_BLOCKLEN]='\0';
}

void XOR(char* first,char* second){
    for(int i=0;i<AES_BLOCKLEN;i++){
        first[i] ^= second[i];
    }
}
void encryptCBC(char* key,BYTE* buff){
    if(isFirst){
        isFirst=false;
        strcpy(previousIV,iv);
    }
    XOR(buff,previousIV);
    encrypt_aes(key,buff);
    strcpy(previousIV,buff);
}
void encryptOFB(char* key,BYTE* buff){
    if(isFirst){
        isFirst=false;
        strcpy(previousIV,iv);
    }
    encrypt_aes(key,previousIV);
    XOR(buff,previousIV);
}
void encrypt(char* key,BYTE* buff,int mode){
    if(mode==CBC_MODE){
        encryptCBC(key,buff);
    }
    else{
        encryptOFB(key,buff);
    }
}

int main(){

    FILE* fd=fopen("fisier.txt","rb");
    int sockfd, connfd, len; 
    struct sockaddr_in servaddr, from; 
  
    SOCKET_TCP_CHECK(sockfd)
    perror("[A]: CREATE SOCKET");
    
    bzero(&servaddr, sizeof(servaddr)); 
    bzero (&from, sizeof (from));
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
    
    BIND_CHECK(sockfd,servaddr);
    perror("[A]: BIND");
  
    LISTEN_CHECK(sockfd);
    perror("[A]: LISTEN");
    
    int client;
    socklen_t length = sizeof (from);
    
    ACCEPT_CHECK(client,sockfd,from,length);
	perror("[A]: ACCEPT");

    int transferedBlocks=0;
    char key[AES_BLOCKLEN];
    int mode;

    while(1){
        //If first block to send or the program already sent Q block
        //we make a call to KM to refresh the key and the encryption mode
        //Then we send the mode,key and a generated IV to B
        if(transferedBlocks==0||transferedBlocks==Q){ 
            if(transferedBlocks==Q){
                transferedBlocks-=Q;
            }
            printf("[A]: Select a crypto  mode ~ 0-CBC, 1-OFB ~ : ");
            fflush(stdout);

            scanf("%d",&mode);
            if(!retriveCryptoMode(key,mode)){
                perror("[A]: Can't Retrive key from KeyManager");
                exit(-1);
            }
            BYTE blockType=0;
            WRITE_CHECK(client,&blockType,sizeof(BYTE));
            WRITE_CHECK(client,&mode,sizeof(int));
            WRITE_CHECK(client,key,AES_BLOCKLEN*sizeof(BYTE));

            generateIV();
            WRITE_CHECK(client,iv,AES_BLOCKLEN*sizeof(BYTE));

            decrypt_aes(K3,key);
            isFirst=true;
        }
        BYTE blockType=1;
        BYTE block[AES_BLOCKLEN];
        int size=0;
        //We read a block from file
        if((size=fread(block,1,AES_BLOCKLEN,fd))<=0){
            blockType=2;
            WRITE_CHECK(client,&blockType,sizeof(BYTE));
            break;
        }
        //
        block[size]='\0';
        block[AES_BLOCKLEN]='\0';

        printf("%s\n",block);
        encrypt(key,block,mode);
        //send encrypted block to 
        WRITE_CHECK(client,&blockType,sizeof(BYTE));
        WRITE_CHECK(client,block,sizeof(BYTE)*AES_BLOCKLEN);

        transferedBlocks++;
    }

    fclose(fd);
    close(sockfd);
    
}