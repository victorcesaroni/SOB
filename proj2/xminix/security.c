/*
 *  funções de criptografia
 */

#include "security.h"

/*
 * buffer: buffer que contem os dados
 * buffer_len: tamanho do buffer de entrada
 * key: chave para criptografia/descriptografia
 * buffer_out: buffer de saida (conterá os dados criptografados)
 * block_size: tamanho do bloco de criptografia
 */
 
int aes_encrypt(__u8 *buffer, size_t buffer_len, const __u8 *key, unsigned int key_len, __u8 *buffer_out, u32 block_size)
{
	struct crypto_cipher *tfm;
	
	tfm = crypto_alloc_cipher("aes", 0, block_size);
	
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "tfm allocation failed\n");
		return -1;
	}
	
	size_t i;	
	size_t num_blocks = buffer_len / block_size;
	size_t last_block_len = buffer_len % block_size;
	
	// verifica se existe um bloco que eh parcialmente completo e "cria" um novo bloco para eles (o buffer de entrada deve ter espaco suficiente e inicializado com 0)
	if (buffer_len % block_size != 0) {
		num_blocks++;
	}
	
	// define a chave
	crypto_cipher_setkey(tfm, key, key_len);
	
	// limpa o buffer de saida
	memset(buffer_out, 0, num_blocks * block_size);
	
	// encripta os blocos
	for (i = 0; i < num_blocks; i++) {    	
		crypto_cipher_encrypt_one(tfm, &buffer_out[i * block_size], &buffer[i * block_size]);
	}
	
	crypto_free_cipher(tfm);
	
	return 0;
}

/*
 * buffer: buffer que contem os dados
 * buffer_len: tamanho do buffer de entrada
 * key: chave para criptografia/descriptografia
 * buffer_out: buffer de saida (conterá os dados criptografados)
 * block_size: tamanho do bloco de criptografia
 */
int aes_decrypt(__u8 *buffer, size_t buffer_len, const __u8 *key, unsigned int key_len, __u8 *buffer_out, u32 block_size)
{
	struct crypto_cipher *tfm;
	
	tfm = crypto_alloc_cipher("aes", 0, block_size);
	
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "tfm allocation failed\n");
		return -1;
	}
	
	size_t i;	
	size_t num_blocks = buffer_len / block_size;
	size_t last_block_len = buffer_len % block_size;
	
	// verifica se existe um bloco que eh parcialmente completo e "cria" um novo bloco para eles (o buffer de entrada deve ter espaco suficiente e inicializado com 0)
	if (buffer_len % block_size != 0) {
		num_blocks++;
	}
	
	// define a chave
	crypto_cipher_setkey(tfm, key, key_len);
	
	// limpa o buffer de saida
	memset(buffer_out, 0, num_blocks * block_size);
	
	// decripta os blocos
	for (i = 0; i < num_blocks; i++) {    	
		crypto_cipher_decrypt_one(tfm, &buffer_out[i * block_size], &buffer[i * block_size]);
	}
	
	crypto_free_cipher(tfm);
	
	return 0;
}

