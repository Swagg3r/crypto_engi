#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "stdint.h"
#include "DES_data.h"

// DES key is 8 bytes long
#define DES_KEY_SIZE 8

//https://github.com/tarequeh/DES

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
		/*
			Algo de chiffrement :
				- Prendre 32 bits de plaintext.
				- Appliquer la fonction d'expentiation (ei[]) jusqu'a 48 bits.
				- Calculer la subkey de 48 bits (pc1[] et pc2[]).
				- Effectuer le XOR entre les deux précedents.
				- Calculer les substitution avec les 8 sboxes :
					- bit 1 to 6	=> S1
					- bit 7 to 12	=> S2
					- bit 13 to 18	=> S3
					- bit 19 to 24	=> S4
					- bit 25 to 30	=> S5
					- bit 31 to 36	=> S6
					- bit 37 to 42	=> S7
					- bit 43 to 48	=> S8
				- La permutation P (p32i[]) de sortie des boites S.
		*/




	} else if (strcmp(argv[1], "decrypt") == 0){
		/* Decryption Mode */
		printf("Decryption mode avec clé = [%s] de taille %d\n",key,size);
		printf("Avec le text de taille %d : [%s]\n",size,text);





	} else {
		printf("Usage : ./des encrypt/decrypt KEY plaintext/ciphertext");
		return 1;
	}
}