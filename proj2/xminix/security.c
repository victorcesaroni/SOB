/*
 *  funções de criptografia
 */

#include "security.h"

static struct aes_helper_t aes_helper;

int setup_cypher(__u8 *key, unsigned int key_len, __u32 block_size)
{
	aes_helper.tfm = crypto_alloc_cipher("aes", 0, 16);
	aes_helper.block_size = block_size;
	memcpy(aes_helper.key, key, key_len);
	aes_helper.key_len = key_len;
	
	if (IS_ERR(aes_helper.tfm)) {
		aes_helper.tfm = NULL;
		printk(KERN_ERR "tfm allocation failed\n");
		return -1;
	}
	
	crypto_cipher_setkey(aes_helper.tfm, aes_helper.key, aes_helper.key_len);
	
	return 0;
}

int unload_cypher(void)
{
	if (IS_ERR(aes_helper.tfm)) {
		printk(KERN_ERR "tfm not allocated\n");
		return -1;
	}
	
	crypto_free_cipher(aes_helper.tfm);
	
	aes_helper.tfm = NULL;
	
	return 0;
}

/*
 * buffer: buffer que contem os dados
 * buffer_len: tamanho do buffer de entrada
 * key: chave para criptografia/descriptografia
 * buffer_out: buffer de saida (conterá os dados criptografados)
 * block_size: tamanho do bloco de criptografia
 */ 
int aes_operation(int type, __u8 *buffer, size_t buffer_len, __u8 *buffer_out)
{
	size_t i, num_blocks;
	
	if (IS_ERR(aes_helper.tfm)) {
		printk(KERN_ERR "tfm not allocated\n");
		return -1;
	}
	
	num_blocks = buffer_len / AES_BLOCK_SIZE;
	
	if (buffer_len % AES_BLOCK_SIZE != 0) {
		num_blocks++;
	}
		
	for (i = 0; i < num_blocks; i++) {
		if (type == AES_ENCRYPT) {
			crypto_cipher_encrypt_one(aes_helper.tfm, &buffer_out[i * AES_BLOCK_SIZE], &buffer[i * AES_BLOCK_SIZE]);
		} else {
			crypto_cipher_decrypt_one(aes_helper.tfm, &buffer_out[i * AES_BLOCK_SIZE], &buffer[i * AES_BLOCK_SIZE]);
		}
	}
		
	return 0;
}

