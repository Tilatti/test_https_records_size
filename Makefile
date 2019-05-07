https_client: https_client.c
	clang https_client.c -g -ggdb -lssl -ltls -lcrypto -o https_client

clean:
	rm https_client
