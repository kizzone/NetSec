#include "../NetSec.h"

int main(int argc, char **argv){

	// File stream
	FILE *fap;
	// Structs for sockets
	struct sockaddr_in serv_addr;
 	struct hostent* server;
 	
 	long i, j;
	long int file_size;
	long blocks_num;
	int lastblock_len=1;
	msg_t pckt[PACKET_SIZE];
	info_t info;

	// Encryption block
	unsigned char m[BLOCK_SIZE];
	// Keys
	unsigned char iv[BLOCK_SIZE];
	unsigned char key[32];
	// MD5 context
	MD5_CTX mdContext;
	// MD5 string
	unsigned char c[MD5_DIGEST_LENGTH];

	//
	
	// Ensure that two args are passed, one being the file to be transferred
	assert(argc==2);
	
	// Get host
	if (( server = gethostbyname(host_name)) == 0) 
	{
		perror("Error resolving local host\n");
		exit(1);
	}

	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = ((struct in_addr *)(server->h_addr))->s_addr;
	serv_addr.sin_port = htons(DEFAULT_PORT);
	
	// Create socket
	int sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if ( sockfd == -1 ){
		perror("Error opening socket\n");
		exit(1);
	}    

	// Connect
	if (connect(sockfd, (void*)&serv_addr, sizeof(serv_addr) ) == -1 ){
		perror("Error connecting to socket\n");
		exit(1);
	}

	// Get Symmetric Key from random values (/dev/urandom)
	strcpy((char *)key, getKey());
	printf("The symmetric key is %s\n", key);

	// Sending the S-Key with RSA
	printf("Sending the encryped symmetric key to server\n\n");
	send_key_to_server(sockfd,key);
	printf("Sent...\n\n");

	// Open file
	fap = fopen(argv[1], "rb");
	if(!fap){
		printf("Could not open %s...\n", argv[1]);
		exit(-1);
	}
	
	// Initialize MD5 Context
	MD5_Init (&mdContext);
	// Init IV
	bzero(iv, BLOCK_SIZE);
	
	// Put filename in infos
	strcpy(info.fileName, argv[1]);
	
	// Check file size in bytes
	fseek(fap, 0L, SEEK_END);
	file_size = ftell(fap);
	rewind(fap);
	
	// Get number of blocks (and packets) for the file and put the latter in infos
	blocks_num =(long)((float)file_size / (float) (BLOCK_SIZE-1))+1;
	info.packetsNum = (long)((float) blocks_num / (float) (PACKET_SIZE))+1;
	
	// Print
	printf("Sending %ld crypted blocks grouped in %ld packets\n",blocks_num, 
															info.packetsNum);
	
	if(send(sockfd, &info,sizeof(info),0) == -1){
		perror("Send error\n");
		exit(-1);
	}

	for (i=0;i<info.packetsNum;i++){
		for(j=0;j<PACKET_SIZE ;j++){
			// READ DATA
			lastblock_len = fread(m, 1, BLOCK_SIZE-1, fap);
			// ENCRYPT
			pckt[j].blockSize = encrypt(m, lastblock_len, key, iv, pckt[j].payload);
			// Update MD5 of cleartext file
			MD5_Update(&mdContext, m, lastblock_len);
		}
		// SEND PACKET
		if(send(sockfd, pckt, sizeof(pckt), 0) == -1){
			perror("Send error\n");
			exit(-1);
		}
		printf("Sent packet %ld of %ld\n", i+1, info.packetsNum);

	}
	
	MD5_Final (c, &mdContext);
	printf("Calculated MD5: ");
	for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", c[i]);
	printf("\n");
	// Send MD5 hash
	if(send(sockfd, c, sizeof(c), 0) == -1){
			perror("Send error\n");
			exit(-1);
		}
	
	fclose(fap);
	printf("Reception of file completed\n");

	return 0;
}







