#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static void dump_buffer(unsigned char *buf, size_t len)
{
	if (!buf) {
		printf("ERROR\n");
		return;
	}
	
	printf("len: %lu\n", len); 
	
	size_t i; 
	for (i = 0; i < len; i++)
	{
		char c = (char)buf[i];		
		
		if (c != '\0' && c != '\n' && (c == 9 || c == 10 || (c >= 32 && c <= 127))) {
			printf("%c", (char)c);
		}
		//else
		//	printf("\\x%02x", (unsigned char)c);		
	}
	
	printf("\n");
}


int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Use: %s [file]\n", argv[0]);
		return -1;
	}
	
	char *file = argv[1];
	
	char op;
	
	do {
		printf("%s > ", file);
		scanf("%c", &op);
		__fpurge(stdin);
		
		char *buff = NULL;
		size_t len = 0;
		int d = 0;
		char min, max;
		size_t i;
		
		switch (op) {
		case 'e':
			exit(0);
			break;
		case 'f':
			printf("fill [len] [rmin] [rmax]\n  >");
			scanf("%lu %c %c", &len, &min, &max);
			buff = calloc(1, len);
			for (i = 0; i < len; i++) {
				buff[i] = (char)(min + (max != min ? rand() % (max - min + 1) : 0));
			}
			d = open(file, O_RDWR);
			write(d, buff, len);
			break;
		case 'r':
			printf("read [len]\n  >");
			scanf("%lu", &len);
			buff = calloc(1, len);
			d = open(file, O_RDWR);
			read(d, buff, len);
			dump_buffer((unsigned char*)buff, len);
			break;
		case 'w':
			printf("write [data]\n  >");
			buff = calloc(1, 4096);
			fgets(buff, 4096, stdin);
			len = strlen(buff);
			d = open(file, O_RDWR);
			write(d, buff, len);
			break;
		case 'd':
			remove(file);
			printf("[remove]\n");
			break;
		case 'c':
			d = open(file, O_CREAT);
			printf("[create] descriptor %d\n", d);
			break; 
		default:
			printf("f [len] [char rand min] [char rand max] - fill a random sequence of len\n");
			printf("r [len] - read len\n");
			printf("w [data] - write\n");
			printf("d - delete\n");
			printf("c - create\n");
			printf("e - exit\n");
			break;
		}
		
		if (buff)
			free(buff);
		if (d != 0)
			close(d);
	} while (op != 'e');
			
	return 0;
}

