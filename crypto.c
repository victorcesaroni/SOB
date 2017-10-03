#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>

/* licenca do modulo */
MODULE_LICENSE("SO B PUCC 2017");
MODULE_AUTHOR("GRUPO");

/*protótipos funções*/
static int device_write(struct file *filp, const char *buff, size_t len, loff_t * off);
static int device_release(struct inode *inode, struct file *file);
static int device_open(struct inode *inode, struct file *file);
static int device_read(struct file *, char *, size_t, loff_t *);

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

/* init */
static int __init crypto_init(void) {
	printk(KERN_INFO "[CRYPTO] Init with key %s.\n", encryption_key);
	return 0;
}

/* exit */
static void __exit crypto_exit(void) {
	printk(KERN_INFO "[CRYPTO] Exit.\n");
}

static int device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
	printk(KERN_ALERT "Arquivo escrito");
}

/*open*/
static int device_open(struct inode *inode, struct file *file)
{
	 printk(KERN_ALERT "Arquivo aberto");
}

/*release*/
static int device_release(struct inode *inode, struct file *file)
{
	 printk(KERN_ALERT "Arquivo liberado");
}


/* definicao das funcoes de init e exit */
module_init(crypto_init);
module_exit(crypto_exit);

