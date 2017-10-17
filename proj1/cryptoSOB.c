#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

#define SUCCESS 0
#define DEVICE_NAME "cryptoSOB"
 
#define SHA1_LENGTH     20
#define AES_BLOCK_SIZE 	16

/* licenca do modulo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("GRUPO");

#define BUFFER_SIZE 256

/*protótipos funções*/
static int device_write(struct file *filp, const char *buff, size_t len, loff_t * off);
static int device_release(struct inode *inode, struct file *file);
static int device_open(struct inode *inode, struct file *file);
static int device_read(struct file *filp, char *buff, size_t len, loff_t * off);

/* parametros do modulo */
static char *key;

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Encryption key");

/*struct de operações*/
static struct file_operations fops = {
 .write = device_write,
 .open = device_open,
 .release = device_release,
 .read = device_read
};

/*variaveis globais*/
static int Major;
static int deviceInUse = 0;

static char content[BUFFER_SIZE]; // espaço para armazenamento de resultados

/* obtem os bytes da encriptacao aes */
int encrypt_aes(char *data, size_t length, char *key, size_t key_length, unsigned char *output, size_t *output_len) {
	struct crypto_cipher *tfm;
	
	*output_len = 0;
	
	tfm = crypto_alloc_cipher("aes", 0, AES_BLOCK_SIZE);
	
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "tfm allocation failed\n");
		return -1;
	}
	
	size_t i;
	
	size_t num_blocks = length / AES_BLOCK_SIZE;
	size_t last_block_len = length % AES_BLOCK_SIZE;
	
	unsigned char block_data[AES_BLOCK_SIZE];
	
	// verifica se existe um bloco que eh parcialmente completo e "cria" um novo bloco para eles (o buffer de entrada deve ter espaco suficiente e inicializado com 0)
	if (length % AES_BLOCK_SIZE != 0) {
		num_blocks++;
	}
	
	crypto_cipher_setkey(tfm, key, key_length);       
	
	// encripta os blocos
	for (i = 0; i < num_blocks; i++) {    	
		memset(block_data, 0, sizeof(block_data)); 
		crypto_cipher_encrypt_one(tfm, block_data, &data[i * AES_BLOCK_SIZE]);
		memcpy(&output[i * AES_BLOCK_SIZE], block_data, sizeof(block_data));
	}
	
	*output_len = num_blocks * AES_BLOCK_SIZE;
	
	crypto_free_cipher(tfm);
	
	return 0;
}

/* obtem os bytes da decriptacao aes */
int decrypt_aes(char *data, size_t length, char *key, size_t key_length, unsigned char *output, size_t *output_len) {
	struct crypto_cipher *tfm;
	
	*output_len = 0;
	
	tfm = crypto_alloc_cipher("aes", 0, AES_BLOCK_SIZE);
		
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "tfm allocation failed\n");
		return -1;
	}
	
	if (length % AES_BLOCK_SIZE != 0) {
		printk(KERN_ERR "invalid block size\n");
		return -2;
	}
	
	size_t i;
	
	size_t num_blocks = length / AES_BLOCK_SIZE;
	
	unsigned char block_data[AES_BLOCK_SIZE];
		
	crypto_cipher_setkey(tfm, key, key_length);       
	
	// decripta os blocos
	for (i = 0; i < num_blocks; i++) {    	
		memset(block_data, 0, sizeof(block_data)); 
		crypto_cipher_decrypt_one(tfm, block_data, &data[i * AES_BLOCK_SIZE]);
		memcpy(&output[i * AES_BLOCK_SIZE], block_data, sizeof(block_data));
	}
	
	*output_len = num_blocks * AES_BLOCK_SIZE;
	
	crypto_free_cipher(tfm);
	
	return 0; 
}


/* obtem os bytes do hash sha1 */
int get_sha1_hash(char *data, size_t length, unsigned char output[SHA1_LENGTH]) {
	struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    
    memset(output, 0, SHA1_LENGTH);
        
    tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
        
    if (IS_ERR(tfm)) {
		printk(KERN_ERR "tfm allocation failed\n");
		return -1;
    }
 
    desc.tfm = tfm;
    desc.flags = 0;
    
    crypto_hash_init(&desc);
    
	sg_init_one(&sg, data, length);
	
	crypto_hash_update(&desc, &sg, length);
	crypto_hash_final(&desc, output);
	
    crypto_free_hash(tfm);
    
    return 0;
}

/* obtem o valor em byte equivalente ao caracter da tabela ascii */
unsigned char char_to_byte(char x) {
    if(x > 47 && x < 58)
    	return x - 48;
    else if(x > 64 && x < 71)
    	return x - 55 ;
    else if(x > 96 && x < 103)
    	return x-87;
	return -1;
}

/* converte 2 caracteres para um byte real */
unsigned char chars_to_byte(char high, char low) {
	return (unsigned char)(char_to_byte(high) << 4) | (char_to_byte(low));
}

/* converte uma byte array formatada como string para uma byte array real */
void convert_to_byte_array(char *str, size_t length, unsigned char *bytes, int *len) {
	int i = 0, j = 0;
	
	for (i = 0; i < length; i += 2) {
		bytes[j++] = chars_to_byte(str[i], str[i + 1]);
	}
	
	*len = j;
}

/* init */
static int __init crypto_init(void) {
	
	//registro do device
	Major = register_chrdev(0,DEVICE_NAME, &fops);
	
	if(Major < 0)
	{
		printk(KERN_ALERT "Registering char failed with %d\n",Major);
		return Major;
	}

	printk(KERN_INFO "[CRYPTO] Init with key %s.\n", key);
	printk(KERN_INFO "mknod /dev/%s c %d 0\n", DEVICE_NAME, Major);
	
	return SUCCESS;
}

/* exit */
static void __exit crypto_exit(void) {
	
	//liberacao do device
	 __unregister_chrdev(Major,0,256, DEVICE_NAME);  
			
	printk(KERN_INFO "[CRYPTO] Exit.\n");
}

/* write */
static int device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
	printk(KERN_INFO "[CRYPTO] Write request %d bytes. data: %s.\n", len, buff);
	
	unsigned char bytes[BUFFER_SIZE];
	unsigned char result[BUFFER_SIZE];
	char raw_data[BUFFER_SIZE];
	char data[BUFFER_SIZE];
	
	size_t bytes_len = 0;
	size_t result_len = 0;
	size_t i;
	
	char op = buff[0];
	
	memset(data, 0, sizeof(data));	
	memcpy(data, (char*)(buff + 2), len - 2);
	
	size_t data_len = strlen(data);
	size_t key_len = strlen(key);
	
	if (data_len > BUFFER_SIZE) {
		data_len = BUFFER_SIZE;
	}
	
	memset(raw_data, 0, sizeof(raw_data));	
	memcpy(raw_data, data, data_len);
	
	memset(result, 0, sizeof(result));
	memset(bytes, 0, sizeof(bytes));
	
	// converte a byte array formatada como string para uma byte array real
	convert_to_byte_array(data, data_len, bytes, &bytes_len); 
		
	strcpy(content, "ERROR");
	
	switch (op) {
		case 'c':
			// encripta usando aes
			if (0 == encrypt_aes(data, data_len, key, key_len, result, &result_len)) {			
				strcpy(content, "");
				for (i = 0; i < result_len; i++) {
					sprintf(content, "%s%02x", content, result[i]);
				}
			}
			break;
			
		case 'd':
			// decripta usando aes
			if (0 == decrypt_aes(bytes, bytes_len, key, key_len, result, &result_len)) {			
				strcpy(content, "");
				for (i = 0; i < result_len; i++) {
					sprintf(content, "%s%c", content, result[i]);
				}
			}
			break;
		
		case 'h':
			// obtem o hash sha1
			if (0 == get_sha1_hash(data, data_len, result)) {			
				strcpy(content, "");
				for (i = 0; i < SHA1_LENGTH; i++) {
					sprintf(content, "%s%02x", content, result[i]);
				}
			}
			break;
	}
	
	// simula numero de bytes escritos
	return len;
}

/* read */
static int device_read(struct file *filp, char *buff, size_t len, loff_t * off)
{
	printk(KERN_INFO "[CRYPTO] Read request %d bytes.\n", len);
	
	if (len > BUFFER_SIZE) {
		printk(KERN_ALERT "[CRYPTO] Warning: Bad read request (%d bytes).\n", len);	
		len = BUFFER_SIZE;
	}
	
	// copy_to_user retorna o numero de bytes que puderam ser lidos do buffer do usuario
	int bytes_read = len - copy_to_user(buff, content, len);
	
	// retorna o total de bytes que foram lidos com sucesso
	return bytes_read;
}

/*open*/
static int device_open(struct inode *inode, struct file *file)
{	
	printk(KERN_INFO "[CRYPTO] Open request.\n");
	 
	if(deviceInUse)
	{
		//dispositivo em uso
		return -EBUSY;
	}
	
	//define dispositivo como "em uso"
	deviceInUse++;
	
	if(try_module_get(THIS_MODULE) == false)
	{
		//dispositivo em uso
		return -EBUSY;
	}

	return SUCCESS;
}

/*release*/
static int device_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "[CRYPTO] Close request.\n");

	//define dispositivo como "liberado"
	deviceInUse--;

	module_put(THIS_MODULE);	 

	return SUCCESS;
}


/* definicao das funcoes de init e exit */
module_init(crypto_init);
module_exit(crypto_exit);

