#include <linux/crypto.h>

#define AES_MIN_KEY_SIZE	16
#define AES_MAX_KEY_SIZE	32
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define AES_BLOCK_SIZE		16
#define AES_MAX_KEYLENGTH	(15 * 16)
#define AES_MAX_KEYLENGTH_U32	(AES_MAX_KEYLENGTH / sizeof(u32))

enum aes_operation_type_t {
	AES_ENCRYPT = 0,
	AES_DECRYPT = 1,
};

struct aes_helper_t {
	struct crypto_cipher *tfm;
	__u32 block_size;
	char key[AES_MAX_KEYLENGTH];
	unsigned int key_len;
};

extern int setup_cypher(__u8 *key, unsigned int key_len, __u32 block_size);
extern int unload_cypher(void);

extern int aes_operation(int type, __u8 *buffer, size_t buffer_len);

