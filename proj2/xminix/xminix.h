#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/highuid.h>
#include <linux/vfs.h>
#include <linux/writeback.h>

extern void dump_buffer(unsigned char *buf, size_t size);		
extern int xminix_block_read_full_page(struct page *page, get_block_t *get_block);
extern int xminix_block_write_full_page(struct page *page, get_block_t *get_block, struct writeback_control *wbc);

