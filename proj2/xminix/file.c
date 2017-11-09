/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include <linux/uio.h>
#include "minix.h"

static void dump_buffer(unsigned char *buf, unsigned size)
{
	printk("size: %d %x\n", size, buf); 
	unsigned i; 
	for (i = 0; i < size; i++)
	{
		char c = (char)buf[i];		
		
		if (c != '\0' && c != '\n' && (c == 9 || c == 10 || (c >= 32 && c <= 127))) {
			printk("%c", (char)c);
		}
		//else
		//	printk("\\x%02x", (unsigned char)c);		
	}
	
	printk("\n");
}


/*
struct iov_iter {
	int type;
	size_t iov_offset;
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
	};
	unsigned long nr_segs;
};

struct iovec
{
	void __user *iov_base;	/* BSD uses caddr_t (1003.1g requires void *) * /
	__kernel_size_t iov_len; /* Must be size_t (1003.1g) * /
};

struct kvec {
	void *iov_base; /* and that should *never* hold a userland pointer * /
	size_t iov_len;
};

struct bio_vec {
	struct page	*bv_page;
	unsigned int	bv_len;
	unsigned int	bv_offset;
};

*/

ssize_t xminix_file_write_iter(struct kiocb *iocb, struct iov_iter *from) {
		
	printk("xminix_file_write_iter\n");
	printk("%d %d\n", from->nr_segs, from->count);
	
	//dump_buffer(from->kvec->iov_base, from->kvec->iov_len);
	
	ssize_t ret = generic_file_write_iter(iocb, from);	
	
	return ret;
}


/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= xminix_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};
