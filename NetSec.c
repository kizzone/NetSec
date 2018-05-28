#include "NetSec.h"

// Encrypt
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,  unsigned char *iv, unsigned char *ciphertext){

	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
	
	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();
		
	// Initialize encryption function (AES 256 BIT CBC MODE)
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	// Encryption update (to be repeated for each block?)
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	// Finalise the encryption. Further ciphertext bytes may be written 
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
		handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return ciphertext_len;
}

// Decrypt
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();
	
	// Decrypt init (AES 256 CBC)
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();
	
	// Decrypt update
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
		
	plaintext_len = len;
	
	/* Finalise the decryption.*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
		handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

//
void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}



void send_key_to_server(int socket_addr, unsigned char* skey){
	
	RSA *rsa = NULL; //rsa struct for storing the .pem data
	FILE *pemFile; //used for RSA public key
	unsigned char encrypted[256];//symmetric key crypted with RSA

    //******************** Encrypt symmetric key*******************************
	if ((pemFile = fopen("public.pem", "rt")) && (rsa = PEM_read_RSAPublicKey(pemFile, NULL, NULL, NULL))){
		fprintf(stderr, "\nReading the public key...\n");
		RSA_public_encrypt(strlen( (char*) skey), (unsigned char *)skey, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
		fclose(pemFile);

	}else{
		fprintf(stderr,"ERROR on encrypt and sending symmetric key\n\n");
		exit(EXIT_FAILURE);
	}

	if(send(socket_addr, encrypted, LEN(encrypted)*sizeof(char), 0) == -1){
		perror("Error on sending the encrypted symmetric keys\n");
		exit(EXIT_FAILURE);
	}

}


//// extract the  symmetric key from rsa encryption
unsigned char* decrypt_RSA_key(unsigned char* encrypted ){

	RSA *rsa = NULL; //rsa struct for storing the .pem data
	FILE *pemFile; //used for RSA public key
	unsigned char *decrypted;

	//********************Decrypt server side*******************************
	decrypted = malloc(sizeof(char) * 33);
	pemFile = fopen("private.pem", "rt");
	if ( (rsa = PEM_read_RSAPrivateKey(pemFile, NULL, NULL, NULL))  && pemFile != NULL) {
		
		RSA_private_decrypt(RSA_size(rsa), encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
		ERR_load_crypto_strings();
		char * err = (char *)malloc(130);
		ERR_error_string(ERR_get_error(), err);
		//fprintf(stderr, "Error decrypting message: %s\n", err);
		} else{
			fprintf(stderr,"ERROR on decrypting  RSA");
			exit(EXIT_FAILURE);
		}

		fclose(pemFile);
		decrypted[32] = '\0';
		//printf("%s\n", decrypted);
		return decrypted;

}

// Get a key for generating a random symmetric key (need 16 bytes)
char * getKey(){
	FILE *f;
	int i;
	char random[16];
	char *string;
	string = malloc(sizeof(char)*BLOCK_SIZE*2+1);
	f = fopen("/dev/urandom", "rb");
	fread(random, 1, sizeof(random), f);
	// Copy hex values inside a string
	for (i=0;i<BLOCK_SIZE;i++){
		sprintf(&string[i*2], "%02x", random[i]);
	}
	string[32] = '\0';
	return string;
}

