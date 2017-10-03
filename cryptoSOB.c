#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>

#define DEVICE_NAME "cryptoSOB"

/* licenca do modulo */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("GRUPO");


/*protótipos funções*/
static int device_write(struct file *filp, const char *buff, size_t len, loff_t * off);
static int device_release(struct inode *inode, struct file *file);
static int device_open(struct inode *inode, struct file *file);
static int device_read(struct file *filp, char *buff, size_t len, loff_t * off);

/* parametros do modulo */
static char encryption_key[4096];

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
	return 0;
}

/* exit */
static void __exit crypto_exit(void) {
	
	//liberacao do device
	int ret  = unregister_chrdev(Major, DEVICE_NAME); //ERRO AQUI 
	
	if(ret < 0)
	{
		printk(KERN_ALERT "Error in unregister_chrdev: %d\n",ret);
	}
	
	printk(KERN_INFO "[CRYPTO] Exit.\n");
}

/* write */
static int device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
	printk(KERN_ALERT "[CRYPTO] Write request %d bytes: %s.\n", len, buff);
	
	return 0;
}

/* read */
static int device_read(struct file *filp, char *buff, size_t len, loff_t * off)
{
	printk(KERN_ALERT "[CRYPTO] Read request %d bytes.\n", len);
	
	return 0;
}

/*open*/
static int device_open(struct inode *inode, struct file *file)
{	
	 
	if(deviceInUse)
	{
		return -EBUSY;	//dispositivo em uso
	}
		
	deviceInUse++;	//define dispositivo como "em uso"
	try_module_get(THIS_MODULE);

	 return 0;
}

/*release*/
static int device_release(struct inode *inode, struct file *file)
{
	deviceInUse--;//define dispositivo como "liberado"

	module_put(THIS_MODULE);	 

	 return 0;
}


/* definicao das funcoes de init e exit */
module_init(crypto_init);
module_exit(crypto_exit);

