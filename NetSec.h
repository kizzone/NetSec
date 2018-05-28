#ifndef Netsec
	#define NetSec

#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* for strings */
#include <sys/socket.h> /* for sockets */
#include <fcntl.h> /* for fcntl() on socket */
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h> /* for sockaddr_in and such */
#include <arpa/inet.h> /* for in_addr and such */
#include <unistd.h> /* for close() */
#include <netdb.h>
#include <assert.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <errno.h>
//======================================================================================================================
//#define SOURCE "foo.pdf" //define for source file to send
//#define DEST "bar.pdf"	//define for destination file 
//======================================================================================================================
#define DEFAULT_PORT 8000
#define BLOCK_SIZE 16	//block size for AES encryption
#define PACKET_SIZE 64	//number of block of 16B to send on socket
#define host_name "127.0.0.1"	//host name
//======================================================================================================================
//======================================================================================================================
#define LEN(X) sizeof(X)/sizeof(*X)
#define DEBUG() printf("\033[1;36m\tLine %d of file '%s'\033[0m\n", __LINE__, __FILE__); //debug stamp
// int error checking
#define CHECK_RETURN(X) do{\
	int return_val = (X);\
	if (return_val != 0) { \
			fprintf(stderr, "Runtime error: returned %d at %s:%d", return_val, __FILE__, __LINE__);\
			exit (EXIT_FAILURE);\
	}\
} while(0);
//======================================================================================================================

// Infos on file
typedef struct {
	char fileName[256];
	long packetsNum;
} info_t;

// Struct of sended message  
typedef struct {
	int blockSize;
	unsigned char payload[BLOCK_SIZE];
} msg_t;


void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void send_key_to_server(int socket_addr, unsigned char* skey);
unsigned char* decrypt_RSA_key(unsigned char* encrypted );
char * getKey();
#endif
