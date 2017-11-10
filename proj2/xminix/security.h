#include <linux/crypto.h>

extern int aes_encrypt(__u8 *buffer, size_t buffer_len, const __u8 *key, unsigned int key_len, __u8 *buffer_out, u32 block_size);
extern int aes_decrypt(__u8 *buffer, size_t buffer_len, const __u8 *key, unsigned int key_len, __u8 *buffer_out, u32 block_size);

