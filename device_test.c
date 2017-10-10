#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main(int argc, char *argv[]) {
	if (argc != 3) {
		printf("Use: %s [operation] [data]\n", argv[0]);
		return -1;
	}

	char op = argv[1][0];
	char *data = argv[2];
	char buff[256];
	char buff2[256];
	memset(buff, 0x00, sizeof(buff));
	
	int d = open("/dev/cryptoSOB", O_RDWR);
		
	// executa a escrita
	sprintf(buff2, "%c %s", op, data);
	
	write(d, buff2, strlen(buff2));
	close(d);
	
	d = open("/dev/cryptoSOB", O_RDWR);
	
	// executa a leitura
	read(d, buff, 256);
	close(d);
	
	// exibe a resposta
	printf("Result: %s\n", buff);
	
	return 0;
}
