all: Client Server
Client : ClientF/client.c 
	gcc -Wall  ClientF/client.c NetSec.c -o ClientF/client -lcrypto 
Server : ServerF/server.c 
	gcc -Wall  ServerF/server.c  NetSec.c -o ServerF/server  -lcrypto 
