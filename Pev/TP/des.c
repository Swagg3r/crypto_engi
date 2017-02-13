#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


//#include "DES_data.h"

// DES key is 8 bytes long
#define DES_KEY_SIZE 8

int main(int argc, char* argv[]) {
	//short int padding;
	char* text;
	int size;

	if (argc < 2) {
		printf("Usage : ./des encrypt/decrypt KEY plaintext/ciphertext\n");
		return 1;
	}

	char* key = (char*) malloc(8*sizeof(char));
	strcpy (key,argv[2]);

	size = strlen(argv[3]);
	text = (char*) malloc(size*sizeof(char));
	strcpy (text,argv[3]);

	if (strcmp(argv[1], "encrypt") == 0){
		/* Encryption mode */
		printf("Encryption mode avec clé = [%s]\n",key);
		printf("Avec le text de taille %d : [%s]\n",size,text);
	} else if (strcmp(argv[1], "decrypt") == 0){
		/* Decryption Mode */
		printf("Decryption mode avec clé = [%s] de taille %d\n",key,size);
		printf("Avec le text de taille %d : [%s]\n",size,text);;
	} else {
		printf("Usage : ./des encrypt/decrypt KEY plaintext/ciphertext");
		return 1;
	}
}