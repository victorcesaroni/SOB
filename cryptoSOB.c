#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/scatterlist.h>

#define SUCCESS 0
#define DEVICE_NAME "cryptoSOB"
 
#define SHA1_LENGTH     20
#define AES_BLOCK_SIZE 	16

/* licenca do modulo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("GRUPO");

#define BUFFER_SIZE (1024 * 10) // esse dispositivo irá suportar um armazenamento de 10KB

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

void encrypt_aes(char *data, int length, char *key, int key_length, char *output) {
	struct crypto_cipher *tfm;
	
	tfm = crypto_alloc_cipher("aes", 0, AES_BLOCK_SIZE);
	
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "tfm allocation failed\n");
		return;
    }
    
    int i, j;
    
    /*printk(KERN_INFO "Encrypt: ");
    for (i = 0; i < length; i++) {
    	printk(KERN_INFO "\\x%02x", (unsigned char)data[i]);
    }
    printk(KERN_INFO"\n");*/
    
    int div = length / AES_BLOCK_SIZE;
    int modd = length % AES_BLOCK_SIZE;
    
    if(modd > 0)  
        div++;
          
    int count = div;

    crypto_cipher_setkey(tfm, key, key_length);  
     
    output[0] = '\0';    
    for(i = 0; i < count; i++) {
    	char tmp[AES_BLOCK_SIZE];
    	memset(tmp, 0x00, sizeof(tmp));
    	
        crypto_cipher_encrypt_one(tfm, tmp, &data[i * AES_BLOCK_SIZE]);
        
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
        	unsigned char b[3];        	 
        	sprintf(b, "%02x", (unsigned char)tmp[j]);        
			strcat(output, b);
        }
    }
    
    crypto_free_cipher(tfm);   
}

void decrypt_aes(char *data, int length, char *key, int key_length, char *output) {
	struct crypto_cipher *tfm;
	
	tfm = crypto_alloc_cipher("aes", 0, AES_BLOCK_SIZE);
	
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "tfm allocation failed\n");
		return;
    }
    
    int i, j;
    
    /*printk(KERN_INFO "Decrypt: ");
    for (i = 0; i < length; i++) {
    	printk(KERN_INFO "\\x%02x", (unsigned char)data[i]);
    }
    printk(KERN_INFO "\n");*/
    
    int div = length / AES_BLOCK_SIZE;  
    int modd = length % AES_BLOCK_SIZE;  
    
    if(modd > 0)  
        div++;
          
    int count = div;

    crypto_cipher_setkey(tfm, key, key_length);  
     
    output[0] = '\0';
    for(i = 0; i < count; i++) {
    	char tmp[AES_BLOCK_SIZE];
    	memset(tmp, 0x00, sizeof(tmp));
    	
        crypto_cipher_decrypt_one(tfm, tmp, &data[i * AES_BLOCK_SIZE]);
        
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
        	unsigned char b[3];        	 
        	sprintf(b, "%c", (unsigned char)tmp[j]);        
			strcat(output, b);
        }
    }
    
    crypto_free_cipher(tfm);   
}


/*https://davejingtian.org/2014/06/18/crypto-use-linux-kernel-crypto-api/*/
void get_sha1_hash(char *data, int length, char output[41]) {
	struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    
    char hash[SHA1_LENGTH];
    
    memset(hash, 0x00, sizeof(hash));
    
    int i;

    tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    
    if (IS_ERR(tfm)) {
		printk(KERN_ERR "tfm allocation failed\n");
		return;
    }
 
    desc.tfm = tfm;
    desc.flags = 0;
    
    crypto_hash_init(&desc);
    
	sg_init_one(&sg, data, length);
	
	crypto_hash_update(&desc, &sg, length);
	crypto_hash_final(&desc, hash);
 
	output[0] = '\0';
	// converte o resultado para uma string
	for (i = 0; i < SHA1_LENGTH; i++) {
		unsigned char b[3];
		sprintf(b, "%02x", (unsigned char)hash[i]);
		strcat(output, b);
    }
    
    crypto_free_hash(tfm);
}

// obtem o valor em byte equivalente ao caracter da tabela ascii
unsigned char char_to_byte(char x) {
    if(x > 47 && x < 58)
    	return x - 48;
    else if(x > 64 && x < 71)
    	return x - 55 ;
    else if(x > 96 && x < 103)
    	return x-87;
	return -1;
}

// converte 2 caracteres para um byte real
unsigned char chars_to_byte(char high, char low) {
	return (unsigned char)(char_to_byte(high) << 4) | (char_to_byte(low));
}

void convert_to_byte_array(char *str, unsigned char *bytes, int *len) {
	int i = 0, j = 0;
	int max = strlen(str);

	for (i = 0; i < max; i += 2) {
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
	
	char op;
	char data[BUFFER_SIZE];
	unsigned char bytes[BUFFER_SIZE];
	char result[BUFFER_SIZE];
	
	sscanf(buff, "%c %s", &op, data);	
	
	int bytes_len = 0;
	
	// converte a byte array formatada como string para uma byte array real
	convert_to_byte_array(data, bytes, &bytes_len); 
	
	int data_len = strlen(data);
	int key_len = strlen(key);
	
	switch (op) {
		case 'c':
			// encripta usando aes
			encrypt_aes(data, data_len, key, key_len, result);
			sprintf(content, "ENCRYPTED: %s", result);
			break;
			
		case 'd':
			// decripta usando aes
			decrypt_aes(bytes, bytes_len, key, key_len, result);
			sprintf(content, "DECRYPTED: %s", result);
			break;
		
		case 'h':
			// obtem o hash sha1
			get_sha1_hash(data, data_len, result);		
			sprintf(content, "HASH: %s", result);
			break;
			
		default:
			strcpy(content, "ERROR");
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

