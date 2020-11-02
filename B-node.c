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
#define A_PORT 8081
#define KM_PORT 8080

#define CBC_MODE 0
#define OFB_MODE 1
#define K3 "2b7e151628aed2a6abf7158809cf4f3c"
#define Q 10


typedef unsigned char       BYTE;
typedef unsigned int        DWORD;


#define SOCKET_TCP_CHECK(descriptor)      					if((descriptor = socket(AF_INET, SOCK_STREAM,0)) == -1){ perror("[B]: Socket error "); return errno;}

#define READ_CHECK(from,in,size)                   			if(read(from,in,size)<0){perror("[B]: Read error "); return errno;}
#define WRITE_CHECK(from,in,size)                   		if(write(from,in,size)<0){perror("[B]: Write error "); return errno;}
#define CONNECT_CHECK(descriptor,server)            if( connect(descriptor,(struct sockaddr *) &server,sizeof (struct sockaddr))==-1){perror("[B]: Connect error "); return errno; }

#define FUNCT_CONNECT_CHECK(descriptor,server)            if( connect(descriptor,(struct sockaddr *) &server,sizeof (struct sockaddr))==-1){perror("[B]: Connect error "); return false; }
#define FUNCT_SOCKET_TCP_CHECK(descriptor)      					if((descriptor = socket(AF_INET, SOCK_STREAM,0)) == -1){ perror("[B]: Socket error "); return false;}
#define FUNCT_READ_CHECK(from,in,size)                   			if(read(from,in,size)<0){perror("[B]: Read error "); return false;}
#define FUNCT_WRITE_CHECK(from,in,size)                   		if(write(from,in,size)<0){perror("[B]: Write error "); return false;}
#define FUNCT_CONNECT_CHECK(descriptor,server)            if( connect(descriptor,(struct sockaddr *) &server,sizeof (struct sockaddr))==-1){perror("[B]: Connect error "); return false; }


bool isFirst=true;
BYTE iv[AES_BLOCKLEN],previousIV[AES_BLOCKLEN];

void encrypt_aes(const char* key,BYTE* buff){
   struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    
    int block=0;
    while(block<strlen(buff)){
        AES_ECB_encrypt(&ctx, buff+block);
        block+=AES_BLOCKLEN;
    }
    
}
void decrypt_aes(const char* key,BYTE* buff){
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    
    int block=0;
    while(block<strlen(buff)){
        AES_ECB_decrypt(&ctx, buff+block);
        block+=AES_BLOCKLEN;
    }
    
}
void XOR(char* first,char* second){
    for(int i=0;i<AES_BLOCKLEN;i++){
        first[i] ^= second[i];
    }
}

void decryptCBC(char* key,BYTE* buff){
    if(isFirst){
        strcpy(previousIV,iv);
        isFirst=false;
    }
    BYTE previousBuff[AES_BLOCKLEN];
    strcpy(previousBuff,buff);
    
    decrypt_aes(key,buff);
    XOR(buff,previousIV);
    strcpy(previousIV,previousBuff);

}
void decryptOFB(char* key,BYTE* buff){
    if(isFirst){
        strcpy(previousIV,iv);
        isFirst=false;
    }
    encrypt_aes(key,previousIV);
    XOR(buff,previousIV);
}

void decrypt(char* key,BYTE* buff,int mode){
    if(mode == CBC_MODE){
        decryptCBC(key,buff);
    }
    else{
        decryptOFB(key,buff);
    }
}
int main(){

    FILE* fd=fopen("fisier_dec.txt","w");
    int serverDescriptor;
    struct sockaddr_in server;

    SOCKET_TCP_CHECK(serverDescriptor);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons (A_PORT);
    CONNECT_CHECK(serverDescriptor,server);

    int mode;
    BYTE key[AES_BLOCKLEN] ;
    BYTE blockType=0;
    
    while(blockType!=2){
        //0--The server will send the encryption mode,key(encrypted) and iv
        //1--Server will send block of encrypted data
        READ_CHECK(serverDescriptor,&blockType,sizeof(BYTE));
        if(blockType==0){
            fflush(stdout);
            READ_CHECK(serverDescriptor,&mode,sizeof(int));
            READ_CHECK(serverDescriptor,key,AES_BLOCKLEN*sizeof(BYTE));
            READ_CHECK(serverDescriptor,iv,AES_BLOCKLEN*sizeof(BYTE));
            //flag to signal that the next block is the first using the new
            // encryption method
            isFirst=true;
            decrypt_aes(K3,key);
        }
        else if(blockType==1){
            fflush(stdout);
            BYTE block[AES_BLOCKLEN];
            
            READ_CHECK(serverDescriptor,block,AES_BLOCKLEN*sizeof(BYTE));
            block[AES_BLOCKLEN]='\0';
            decrypt(key,block,mode);
            printf("%s\n",block);
            fprintf(fd,"%s",block);
        }
        else{break;}
    }
    fclose(fd);
    
}