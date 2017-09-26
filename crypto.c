#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/stat.h>

/* licenca do modulo */
MODULE_LICENSE("SO B PUCC 2017");
MODULE_AUTHOR("GRUPO");

/* parametros do modulo */
static char encryption_key[4096];

module_param(encryption_key, charp, 0000);
MODULE_PARM_DESC(encryption_key, "Encryption key");

/* init */
static int __init crypto_init(void) {
	printk(KERN_INFO "[CRYPTO] Init with key %s.\n", encryption_key);
	return 0;
}

/* exit */
static void __exit crypto_exit(void) {
	printk(KERN_INFO "[CRYPTO] Exit.\n");
}

/* definicao das funcoes de init e exit */
module_int(crypto_init);
module_exit(crypto_exit);

