#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>

#define SUCCESS 0
#define DEVICE_NAME "cryptoSOB"

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
static char *encryption_key;

module_param(encryption_key, charp, 0000);
MODULE_PARM_DESC(encryption_key, "Encryption key");

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

/* init */
static int __init crypto_init(void) {
	
	//registro do device
	Major = register_chrdev(0,DEVICE_NAME, &fops);
	
	if(Major < 0)
	{
		printk(KERN_ALERT "Registering char failed with %d\n",Major);
		return Major;
	}

	printk(KERN_INFO "[CRYPTO] Init with key %s.\n", encryption_key);
	printk(KERN_INFO "'mknod /dev/%s c %d 0'.\n", DEVICE_NAME, Major);
	
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
	char op;
	char data[BUFFER_SIZE];
	
	printk(KERN_ALERT "[CRYPTO] Write request %d bytes. raw_data: %s.\n", len, buff);
		
	sscanf(buff, "%c %s", &op, data);
	
	switch (op) {
		case 'c':
			strcpy(content, "ENCRIPT ");
			strcat(content, data);
			break;
			
		case 'd':
			strcpy(content, "DECRIPT ");
			strcat(content, data);
			break;
		
		case 'h':
			strcpy(content, "HASH ");
			strcat(content, data);
			break;
			
		default:
			strcpy(content, "ERROR ");
			strcat(content, data);
			break;
	}
	
	// bytes escritos
	return len;
}

/* read */
static int device_read(struct file *filp, char *buff, size_t len, loff_t * off)
{
	printk(KERN_ALERT "[CRYPTO] Read request %d bytes.\n", len);
	
	if (len > BUFFER_SIZE) {
		printk(KERN_ALERT "[CRYPTO] Warning: Bad read request (%d bytes).\n", len);	
		len = BUFFER_SIZE;
	}
	
	int bytes_read = len - copy_to_user(buff, content, len);
	
	return bytes_read;
}

/*open*/
static int device_open(struct inode *inode, struct file *file)
{	
	printk(KERN_ALERT "[CRYPTO] Open request.\n");
	 
	if(deviceInUse)
	{
		return -EBUSY;	//dispositivo em uso
	}
		
	deviceInUse++;	//define dispositivo como "em uso"
	
	if(try_module_get(THIS_MODULE) == false)
	{
		return -EBUSY; //dispositivo em uso
	}

	return SUCCESS;
}

/*release*/
static int device_release(struct inode *inode, struct file *file)
{
	printk(KERN_ALERT "[CRYPTO] Close request.\n");

	deviceInUse--;//define dispositivo como "liberado"

	module_put(THIS_MODULE);	 

	return SUCCESS;
}


/* definicao das funcoes de init e exit */
module_init(crypto_init);
module_exit(crypto_exit);

