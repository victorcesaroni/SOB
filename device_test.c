#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	if (argc != 3) {
		printf("Use: %s [operation] [data]\n", argv[0]);
		return -1;
	}

	char op = argv[1][0];
	char *data = argv[2];
	
	FILE *device = fopen("/dev/cryptoSOB", "w");
	
	if (NULL == device) {
		printf("Failed to open crypto.\n");
		return -2;
	}
	
	printf("Pressione qualquer tecla para escrever\n");
	getchar();
	
	// executa a escrita no device
	fprintf(device, "%c %s", op, data);
	fclose(device);
	
	printf("Pressione qualquer tecla para continuar\n");
	getchar();
	
	// espera enquanto o device estiver ocupado
	//do {
		device = fopen("/dev/cryptoSOB", "r");
	
		if (NULL == device) {
			printf("Device not ready yet.\n");
			usleep(250000);
			return -3;
		}
	//} while(NULL == device);
	
	// le a resposta
	char buff[4096];
	
	printf("Pressione qualquer tecla para ler\n");
	getchar();
	
	fread(buff, 4096, 1, device);
	fclose(device);
	
	// exibe a resposta
	printf("Result: %s\n", buff);
	
	return 0;
}
