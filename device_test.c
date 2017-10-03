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
	
	FILE *device = fopen("devcrypto", "w");
	
	if (NULL == device) {
		printf("Failed to open crypto.\n");
		return -2;
	}
	
	// executa a escrita no device
	fprintf(device, "%c %s", op, data);
	fclose(device);
	
	device = fopen("devcrypto", "r");
	
	if (NULL == device) {
		printf("Failed to open crypto [2].\n");
		return -3;
	}
	
	char buff[4096];
	
	// espera enquanto o device estiver ocupado
	while (0 != fread(buff, 4096, 1, device)) {
		printf("Device not ready yet.\n");
		usleep(250000);
	}
	
	printf("Result: %s\n", buff);
	
	fclose(device);
	
	return 0;
}
