#include "../NetSec.h"


int main(int argc, char ** argv){

	// File stream
	FILE *fap;
	
	// Structs for sockets
	struct sockaddr_in serv_addr;
	struct sockaddr_in cli_addr;
	
	long i, j;
	int dec_len;
	
	// IV AND KEY
	unsigned char iv[BLOCK_SIZE];
	unsigned char *key ;//= (unsigned char *)"01234567890123456789012345678901";
	unsigned char encrypted[256];//symmetric key crypted with RSA
	char *command;
	
	// Buffer for reception and decryption
	msg_t pckt[PACKET_SIZE];
	info_t info;
	unsigned char decrypted_block[BLOCK_SIZE];
	// MD5 context
	MD5_CTX mdContext;
	// MD5 string
	unsigned char c[MD5_DIGEST_LENGTH];
	unsigned char rc[MD5_DIGEST_LENGTH];

	//


	// Socket opening
	int sockfd = socket( PF_INET, SOCK_STREAM, 0 );  
	if ( sockfd == -1 ) 
	{
		perror("Error opening socket\n");
		exit(1);
	}
	
	int options = 1;
	if(setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, &options, sizeof (options)) < 0) {
		perror("Error on setsockopt\n");
		exit(1);
	}

	bzero( &serv_addr, sizeof(serv_addr) );
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(DEFAULT_PORT);
	// Set IV to zero
	bzero(iv, BLOCK_SIZE);
	// Allocate space for key
	key = malloc(sizeof(char)*33);

	// Address binding to socket
	if ( bind( sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr) ) == -1 ) 
	{
		perror("Error on binding\n");
		exit(1);
	}
	
	// Maximum number of connections in the queue
	if ( listen( sockfd, 20 ) == -1 ) 
	{
		perror("Error on listen\n");
		exit(1);
	}
	// Address size
	socklen_t address_size = sizeof(cli_addr);	
	
	// Main Cycle
	for(;;)	{
		
		// Init MD5 context
		MD5_Init (&mdContext);
		
		// Print
		printf("Waiting for a new connection...\n");
		
		// New connection acceptance		
		int newsockfd = accept( sockfd, (struct sockaddr *)&cli_addr, &address_size );      
		if (newsockfd == -1) 
		{
			perror("Error on accept\n");
			exit(1);
		}

		// Receiving the symmetric key with RSA encryption
		if(recv(newsockfd,encrypted,sizeof(char)*LEN(encrypted),0)==-1){
			perror("Receive error\n");
			exit(-1);
		}

		printf("Received the RSA encrypted symmetric key...\nDecrypting...\n\n");
		
		key = decrypt_RSA_key (encrypted);

		printf("The symmetric key is %s\n",key);

		// Find infos on the packets to receive..
		if(recv(newsockfd,&info,sizeof(info),0)==-1){
			perror("Receive error\n");
			exit(-1);
		}
		// Print how many packets we're gonna receive
		
		// File open in write mode
		fap = fopen(info.fileName, "wb");
		if (!fap)
			fprintf(stderr,"Error opening file\n");
		
		printf("We're going to receive %ld\n", info.packetsNum);
		
		// For each packet received
		// Split in blocks and decrypt them
		for(i=0;i<info.packetsNum;i++){
			if(recv(newsockfd, pckt, sizeof(pckt), 0)==-1){
				perror("Receive error\n");
				exit(-1);
			}
			printf("Received packet %ld of %ld\n", i+1, info.packetsNum);
			for(j=0;j<PACKET_SIZE;j++){
				// Decrypt
				dec_len = decrypt(pckt[j].payload, pckt[j].blockSize, key, iv, decrypted_block);
				// Update MD5
				MD5_Update (&mdContext, decrypted_block, dec_len);
				// Write on file
				fwrite(decrypted_block, 1, dec_len, fap);
			}
		}
		MD5_Final (c, &mdContext);
		// Receive MD5 hash
		if(recv(newsockfd, rc, sizeof(rc), 0)==-1){
				perror("Receive error\n");
				exit(-1);
		}
		
		// Free key
		free(key);
		// Close file stream
		fclose(fap);
		
		printf("Calculated MD5: ");
		for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", c[i]);
		printf("\nReceived MD5: ");
		for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", rc[i]);
		printf("\n");
		if(strncmp((char *) rc, (char *) c, MD5_DIGEST_LENGTH/8*2)!=0){
			perror("Hashes not matching!\n");
			fclose(fap);
			command = malloc(sizeof(char)*(strlen(DEST)+4));
			sprintf(command, "rm %s", DEST);
			system(command);
			free(command);
			exit(-1);
		}
		
	}
	// Close socket
	close(sockfd);
	return 0;
	
}



