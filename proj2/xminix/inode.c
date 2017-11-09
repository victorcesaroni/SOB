/*
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Copyright (C) 1996  Gertjan van Wingerde
 *	Minix V2 fs support.
 *
 *  Modified for 680x0 by Andreas Schwab
 *  Updated to filesystem version 3 by Daniel Aragones
 */

#include <linux/module.h>
#include "minix.h"
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/highuid.h>
#include <linux/vfs.h>
#include <linux/writeback.h>

static int minix_write_inode(struct inode *inode,
		struct writeback_control *wbc);
static int minix_statfs(struct dentry *dentry, struct kstatfs *buf);
static int minix_remount (struct super_block * sb, int * flags, char * data);


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

/*static void dump_buffer_head(struct buffer_head *bh)
{
	printk("b_size: %d %x\n", bh->b_size, bh->b_data); 
	int i; 
	for (i = 0; i < bh->b_size; i++)
	{
		char c = bh->b_data[i];		
		
		if (c != 0 && c != '\n' && (c == 9 || c == 10 || (c >= 32 && c <= 127)))) {
			printk("%c", (char)bh->b_data[i]);
		}
		//else
		//	printk("\\x%02x", (unsigned char)c);		
	}
	
	printk("\n");
}*/

static void minix_evict_inode(struct inode *inode)
{
	printk("minix_evict_inode\n");
	
	truncate_inode_pages_final(&inode->i_data);
	if (!inode->i_nlink) {
		inode->i_size = 0;
		minix_truncate(inode);
	}
	invalidate_inode_buffers(inode);
	clear_inode(inode);
	if (!inode->i_nlink)
		minix_free_inode(inode);
}

static void minix_put_super(struct super_block *sb)
{
	printk("minix_put_super\n");
	
	int i;
	struct minix_sb_info *sbi = minix_sb(sb);

	if (!(sb->s_flags & MS_RDONLY)) {
		if (sbi->s_version != MINIX_V3)	 /* s_state is now out from V3 sb */
			sbi->s_ms->s_state = sbi->s_mount_state;
		mark_buffer_dirty(sbi->s_sbh);
	}
	for (i = 0; i < sbi->s_imap_blocks; i++)
		brelse(sbi->s_imap[i]);
	for (i = 0; i < sbi->s_zmap_blocks; i++)
		brelse(sbi->s_zmap[i]);
	brelse (sbi->s_sbh);
	kfree(sbi->s_imap);
	sb->s_fs_info = NULL;
	kfree(sbi);
}

static struct kmem_cache * minix_inode_cachep;

static struct inode *minix_alloc_inode(struct super_block *sb)
{
	printk("minix_alloc_inode\n");
	
	struct minix_inode_info *ei;
	ei = kmem_cache_alloc(minix_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void minix_i_callback(struct rcu_head *head)
{
	printk("minix_i_callback\n");
	
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(minix_inode_cachep, minix_i(inode));
}

static void minix_destroy_inode(struct inode *inode)
{
	printk("minix_destroy_inode\n");
	
	call_rcu(&inode->i_rcu, minix_i_callback);
}

static void init_once(void *foo)
{
	printk("init_once\n");
	
	struct minix_inode_info *ei = (struct minix_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	printk("init_inodecache\n");
	
	minix_inode_cachep = kmem_cache_create("minix_inode_cache",
					     sizeof(struct minix_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (minix_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	printk("destroy_inodecache\n");
	
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(minix_inode_cachep);
}

static const struct super_operations minix_sops = {
	.alloc_inode	= minix_alloc_inode,
	.destroy_inode	= minix_destroy_inode,
	.write_inode	= minix_write_inode,
	.evict_inode	= minix_evict_inode,
	.put_super	= minix_put_super,
	.statfs		= minix_statfs,
	.remount_fs	= minix_remount,
};

static int minix_remount (struct super_block * sb, int * flags, char * data)
{
	printk("minix_remount\n");
	
	struct minix_sb_info * sbi = minix_sb(sb);
	struct minix_super_block * ms;

	sync_filesystem(sb);
	ms = sbi->s_ms;
	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		return 0;
	if (*flags & MS_RDONLY) {
		if (ms->s_state & MINIX_VALID_FS ||
		    !(sbi->s_mount_state & MINIX_VALID_FS))
			return 0;
		/* Mounting a rw partition read-only. */
		if (sbi->s_version != MINIX_V3)
			ms->s_state = sbi->s_mount_state;
		mark_buffer_dirty(sbi->s_sbh);
	} else {
	  	/* Mount a partition which is read-only, read-write. */
		if (sbi->s_version != MINIX_V3) {
			sbi->s_mount_state = ms->s_state;
			ms->s_state &= ~MINIX_VALID_FS;
		} else {
			sbi->s_mount_state = MINIX_VALID_FS;
		}
		mark_buffer_dirty(sbi->s_sbh);

		if (!(sbi->s_mount_state & MINIX_VALID_FS))
			printk("MINIX-fs warning: remounting unchecked fs, "
				"running fsck is recommended\n");
		else if ((sbi->s_mount_state & MINIX_ERROR_FS))
			printk("MINIX-fs warning: remounting fs with errors, "
				"running fsck is recommended\n");
	}
	return 0;
}

static int minix_fill_super(struct super_block *s, void *data, int silent)
{
	printk("minix_fill_super\n");
	
	struct buffer_head *bh;
	struct buffer_head **map;
	struct minix_super_block *ms;
	struct minix3_super_block *m3s = NULL;
	unsigned long i, block;
	struct inode *root_inode;
	struct minix_sb_info *sbi;
	int ret = -EINVAL;

	sbi = kzalloc(sizeof(struct minix_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	s->s_fs_info = sbi;

	BUILD_BUG_ON(32 != sizeof (struct minix_inode));
	BUILD_BUG_ON(64 != sizeof(struct minix2_inode));

	if (!sb_set_blocksize(s, BLOCK_SIZE))
		goto out_bad_hblock;

	if (!(bh = sb_bread(s, 1)))
		goto out_bad_sb;

	ms = (struct minix_super_block *) bh->b_data;
	sbi->s_ms = ms;
	sbi->s_sbh = bh;
	sbi->s_mount_state = ms->s_state;
	sbi->s_ninodes = ms->s_ninodes;
	sbi->s_nzones = ms->s_nzones;
	sbi->s_imap_blocks = ms->s_imap_blocks;
	sbi->s_zmap_blocks = ms->s_zmap_blocks;
	sbi->s_firstdatazone = ms->s_firstdatazone;
	sbi->s_log_zone_size = ms->s_log_zone_size;
	sbi->s_max_size = ms->s_max_size;
	s->s_magic = ms->s_magic;
	if (s->s_magic == MINIX_SUPER_MAGIC) {
		sbi->s_version = MINIX_V1;
		sbi->s_dirsize = 16;
		sbi->s_namelen = 14;
		s->s_max_links = MINIX_LINK_MAX;
	} else if (s->s_magic == MINIX_SUPER_MAGIC2) {
		sbi->s_version = MINIX_V1;
		sbi->s_dirsize = 32;
		sbi->s_namelen = 30;
		s->s_max_links = MINIX_LINK_MAX;
	} else if (s->s_magic == MINIX2_SUPER_MAGIC) {
		sbi->s_version = MINIX_V2;
		sbi->s_nzones = ms->s_zones;
		sbi->s_dirsize = 16;
		sbi->s_namelen = 14;
		s->s_max_links = MINIX2_LINK_MAX;
	} else if (s->s_magic == MINIX2_SUPER_MAGIC2) {
		sbi->s_version = MINIX_V2;
		sbi->s_nzones = ms->s_zones;
		sbi->s_dirsize = 32;
		sbi->s_namelen = 30;
		s->s_max_links = MINIX2_LINK_MAX;
	} else if ( *(__u16 *)(bh->b_data + 24) == MINIX3_SUPER_MAGIC) {
		m3s = (struct minix3_super_block *) bh->b_data;
		s->s_magic = m3s->s_magic;
		sbi->s_imap_blocks = m3s->s_imap_blocks;
		sbi->s_zmap_blocks = m3s->s_zmap_blocks;
		sbi->s_firstdatazone = m3s->s_firstdatazone;
		sbi->s_log_zone_size = m3s->s_log_zone_size;
		sbi->s_max_size = m3s->s_max_size;
		sbi->s_ninodes = m3s->s_ninodes;
		sbi->s_nzones = m3s->s_zones;
		sbi->s_dirsize = 64;
		sbi->s_namelen = 60;
		sbi->s_version = MINIX_V3;
		sbi->s_mount_state = MINIX_VALID_FS;
		sb_set_blocksize(s, m3s->s_blocksize);
		s->s_max_links = MINIX2_LINK_MAX;
	} else
		goto out_no_fs;

	/*
	 * Allocate the buffer map to keep the superblock small.
	 */
	if (sbi->s_imap_blocks == 0 || sbi->s_zmap_blocks == 0)
		goto out_illegal_sb;
	i = (sbi->s_imap_blocks + sbi->s_zmap_blocks) * sizeof(bh);
	map = kzalloc(i, GFP_KERNEL);
	if (!map)
		goto out_no_map;
	sbi->s_imap = &map[0];
	sbi->s_zmap = &map[sbi->s_imap_blocks];

	block=2;
	for (i=0 ; i < sbi->s_imap_blocks ; i++) {
		if (!(sbi->s_imap[i]=sb_bread(s, block)))
			goto out_no_bitmap;
		block++;
	}
	for (i=0 ; i < sbi->s_zmap_blocks ; i++) {
		if (!(sbi->s_zmap[i]=sb_bread(s, block)))
			goto out_no_bitmap;
		block++;
	}

	minix_set_bit(0,sbi->s_imap[0]->b_data);
	minix_set_bit(0,sbi->s_zmap[0]->b_data);

	/* Apparently minix can create filesystems that allocate more blocks for
	 * the bitmaps than needed.  We simply ignore that, but verify it didn't
	 * create one with not enough blocks and bail out if so.
	 */
	block = minix_blocks_needed(sbi->s_ninodes, s->s_blocksize);
	if (sbi->s_imap_blocks < block) {
		printk("MINIX-fs: file system does not have enough "
				"imap blocks allocated.  Refusing to mount.\n");
		goto out_no_bitmap;
	}

	block = minix_blocks_needed(
			(sbi->s_nzones - sbi->s_firstdatazone + 1),
			s->s_blocksize);
	if (sbi->s_zmap_blocks < block) {
		printk("MINIX-fs: file system does not have enough "
				"zmap blocks allocated.  Refusing to mount.\n");
		goto out_no_bitmap;
	}

	/* set up enough so that it can read an inode */
	s->s_op = &minix_sops;
	root_inode = minix_iget(s, MINIX_ROOT_INO);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto out_no_root;
	}

	ret = -ENOMEM;
	s->s_root = d_make_root(root_inode);
	if (!s->s_root)
		goto out_no_root;

	if (!(s->s_flags & MS_RDONLY)) {
		if (sbi->s_version != MINIX_V3) /* s_state is now out from V3 sb */
			ms->s_state &= ~MINIX_VALID_FS;
		mark_buffer_dirty(bh);
	}
	if (!(sbi->s_mount_state & MINIX_VALID_FS))
		printk("MINIX-fs: mounting unchecked file system, "
			"running fsck is recommended\n");
	else if (sbi->s_mount_state & MINIX_ERROR_FS)
		printk("MINIX-fs: mounting file system with errors, "
			"running fsck is recommended\n");

	return 0;

out_no_root:
	if (!silent)
		printk("MINIX-fs: get root inode failed\n");
	goto out_freemap;

out_no_bitmap:
	printk("MINIX-fs: bad superblock or unable to read bitmaps\n");
out_freemap:
	for (i = 0; i < sbi->s_imap_blocks; i++)
		brelse(sbi->s_imap[i]);
	for (i = 0; i < sbi->s_zmap_blocks; i++)
		brelse(sbi->s_zmap[i]);
	kfree(sbi->s_imap);
	goto out_release;

out_no_map:
	ret = -ENOMEM;
	if (!silent)
		printk("MINIX-fs: can't allocate map\n");
	goto out_release;

out_illegal_sb:
	if (!silent)
		printk("MINIX-fs: bad superblock\n");
	goto out_release;

out_no_fs:
	if (!silent)
		printk("VFS: Can't find a Minix filesystem V1 | V2 | V3 "
		       "on device %s.\n", s->s_id);
out_release:
	brelse(bh);
	goto out;

out_bad_hblock:
	printk("MINIX-fs: blocksize too small for device\n");
	goto out;

out_bad_sb:
	printk("MINIX-fs: unable to read superblock\n");
out:
	s->s_fs_info = NULL;
	kfree(sbi);
	return ret;
}

static int minix_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	printk("minix_statfs\n");
	
	struct super_block *sb = dentry->d_sb;
	struct minix_sb_info *sbi = minix_sb(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);
	buf->f_type = sb->s_magic;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = (sbi->s_nzones - sbi->s_firstdatazone) << sbi->s_log_zone_size;
	buf->f_bfree = minix_count_free_blocks(sb);
	buf->f_bavail = buf->f_bfree;
	buf->f_files = sbi->s_ninodes;
	buf->f_ffree = minix_count_free_inodes(sb);
	buf->f_namelen = sbi->s_namelen;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

static int minix_get_block(struct inode *inode, sector_t block,
		    struct buffer_head *bh_result, int create)
{
	printk("minix_get_block\n");
	
	int ret;
	
	if (INODE_VERSION(inode) == MINIX_V1)
		ret = V1_minix_get_block(inode, block, bh_result, create);	
	else
		ret = V2_minix_get_block(inode, block, bh_result, create);
		
	//dump_buffer(bh_result->b_data, bh_result->b_size);
	
	return ret;
}

static int minix_writepage(struct page *page, struct writeback_control *wbc)
{
	printk("minix_writepage\n");
	
	return block_write_full_page(page, minix_get_block, wbc);
}

static int minix_readpage(struct file *file, struct page *page)
{
	printk("minix_readpage\n");
		
	return block_read_full_page(page,minix_get_block);
}

int minix_prepare_chunk(struct page *page, loff_t pos, unsigned len)
{
	printk("minix_prepare_chunk\n");
	
	return __block_write_begin(page, pos, len, minix_get_block);
}

static void minix_write_failed(struct address_space *mapping, loff_t to)
{
	printk("minix_write_failed\n");
	
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		minix_truncate(inode);
	}
}


// funcao obtida do kernel
static inline int block_size_bits(unsigned int blocksize)
{
	return ilog2(blocksize);
}

// funcao obtida do kernel
static struct buffer_head *create_page_buffers(struct page *page, struct inode *inode, unsigned int b_state)
{
	BUG_ON(!PageLocked(page));

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << ACCESS_ONCE(inode->i_blkbits), b_state);
	return page_buffers(page);
}


// funcao obtida do kernel
int xminix__block_write_begin(struct page *page, loff_t pos, unsigned len,
		get_block_t *get_block)
{
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + len;
	struct inode *inode = page->mapping->host;
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize, bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh=wait;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_CACHE_SIZE);
	BUG_ON(to > PAGE_CACHE_SIZE);
	BUG_ON(from > to);

	head = create_page_buffers(page, inode, 0);
	blocksize = head->b_size;
	bbits = block_size_bits(blocksize);

	block = (sector_t)page->index << (PAGE_CACHE_SHIFT - bbits);

	for(bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start=block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;	
		
		if (block_end <= from || block_start >= to) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
		if (buffer_new(bh))
			clear_buffer_new(bh);
		if (!buffer_mapped(bh)) {
			WARN_ON(bh->b_size != blocksize);
			err = get_block(inode, block, bh, 1);
			if (err)
				break;
					
			if (buffer_new(bh)) {
				unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
				if (PageUptodate(page)) {
					clear_buffer_new(bh);
					set_buffer_uptodate(bh);
					mark_buffer_dirty(bh);
					continue;
				}
				if (block_end > to || block_start < from)
					zero_user_segments(page,
						to, block_end,
						block_start, from);
				continue;
			}
		}
				
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue; 
		}
		if (!buffer_uptodate(bh) && !buffer_delay(bh) &&
		    !buffer_unwritten(bh) &&
		     (block_start < from || block_end > to)) {
		     
			ll_rw_block(READ, 1, &bh);
			*wait_bh++=bh;
		}
		
		// produz efeito de delay
		//printk("xminix__block_write_begin");
		//dump_buffer(bh->b_data, bh->b_size);
	}
	/*
	 * If we issued read requests - let them complete.
	 */
	while(wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
		if (!buffer_uptodate(*wait_bh))
			err = -EIO;
	}
	if (unlikely(err))
		page_zero_new_buffers(page, from, to);
	return err;
}

// funcao obtida do kernel
static int xminix_block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
		unsigned flags, struct page **pagep, get_block_t *get_block)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	int status;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	
	status = xminix__block_write_begin(page, pos, len, get_block);
	if (unlikely(status)) {
		unlock_page(page);
		page_cache_release(page);
		page = NULL;
	}

	*pagep = page;
	return status;
}

static int minix_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	printk("minix_write_begin\n");
		
	int ret;
	
	/*
	aqui conseguimos pegar o tamanho da frase escrita
	char test[PAGE_SIZE];	
	
	struct page *page = *pagep;
	
	printk("%X %X %X %d %d %d\n", pagep, pagep ? *pagep : 0, *pagep ? **(int**)pagep : 0, pos, len, PAGE_SIZE);
		
	copy_from_user(test, page, len);
	
	dump_buffer(pagep, len);
	//dump_buffer(test, len);*/

	ret = xminix_block_write_begin(mapping, pos, len, flags, pagep,
				minix_get_block);
	if (unlikely(ret))
		minix_write_failed(mapping, pos + len);
		
	return ret;
}

static sector_t minix_bmap(struct address_space *mapping, sector_t block)
{
	printk("minix_bmap\n");
	
	return generic_block_bmap(mapping,block,minix_get_block);
}

/*
 * reconstruimos no modulo o generic_write_end e suas principais funções que permitem 
 * chegar ao __block_commit_write, onde podemos obter o tamanho do bloco, a quantidade
 * de blocos que vamos escrever, o tamanho dos dados e conseguimos alterar os dados
 * para possibilitar a criptografia.
 */ 
static int xminix__block_commit_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to)
{
	unsigned block_start, block_end;
	int partial = 0;
	unsigned blocksize;
	struct buffer_head *bh, *head;

	bh = head = page_buffers(page);
	blocksize = bh->b_size;
	
	block_start = 0;
	do {		
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
		} else {
			printk("xminix__block_commit_write");
			int ii = 0;
			for (ii = 0; ii < bh->b_size; ii++) {
				bh->b_data[ii] = 'B';
			}
			//insira criptografia aqui -------------
			dump_buffer(bh->b_data, bh->b_size);
			set_buffer_uptodate(bh);
			mark_buffer_dirty(bh);
		}
		clear_buffer_new(bh);

		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);

	/*
	 * If this is a partial write which happened to make all buffers
	 * uptodate then we can optimize away a bogus readpage() for
	 * the next read(). Here we 'discover' whether the page went
	 * uptodate as a result of this (potentially partial) write.
	 */
	if (!partial)
		SetPageUptodate(page);
	return 0;
}

int xminix_block_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	unsigned start;

	start = pos & (PAGE_CACHE_SIZE - 1);

	if (unlikely(copied < len)) {
		/*
		 * The buffers that were written will now be uptodate, so we
		 * don't have to worry about a readpage reading them and
		 * overwriting a partial write. However if we have encountered
		 * a short write and only partially written into a buffer, it
		 * will not be marked uptodate, so a readpage might come in and
		 * destroy our partial write.
		 *
		 * Do the simplest thing, and just treat any short write to a
		 * non uptodate page as a zero-length write, and force the
		 * caller to redo the whole thing.
		 */
		if (!PageUptodate(page))
			copied = 0;

		page_zero_new_buffers(page, start+copied, start+len);
	}
	flush_dcache_page(page);

	/* This could be a short (even 0-length) commit */
	xminix__block_commit_write(inode, page, start, start+copied);

	return copied;
}

int xminix_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata) {
			
	
	// apenas o generic_write_end reconstruido
	
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	int i_size_changed = 0;

	
	copied = xminix_block_write_end(file, mapping, pos, len, copied, page, fsdata);

	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold i_mutex.
	 *
	 * But it's important to update i_size while still holding page lock:
	 * page writeout could otherwise come in and zero beyond i_size.
	 */
	if (pos+copied > inode->i_size) {
		i_size_write(inode, pos+copied);
		i_size_changed = 1;
	}

	unlock_page(page);
	page_cache_release(page);

	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);
	/*
	 * Don't mark the inode dirty under page lock. First, it unnecessarily
	 * makes the holding time of page lock longer. Second, it forces lock
	 * ordering of page lock and transaction start for journaling
	 * filesystems.
	 */
	if (i_size_changed)
		mark_inode_dirty(inode);
	
	return copied;
}

static const struct address_space_operations minix_aops = {
	.readpage = minix_readpage,
	.writepage = minix_writepage,
	.write_begin = minix_write_begin,
	.write_end = xminix_write_end,
	.bmap = minix_bmap
};

static const struct inode_operations minix_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.getattr	= minix_getattr,
};

void minix_set_inode(struct inode *inode, dev_t rdev)
{
	printk("minix_set_inode\n");
	
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &minix_file_inode_operations;
		inode->i_fop = &minix_file_operations;
		inode->i_mapping->a_ops = &minix_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &minix_dir_inode_operations;
		inode->i_fop = &minix_dir_operations;
		inode->i_mapping->a_ops = &minix_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &minix_symlink_inode_operations;
		inode->i_mapping->a_ops = &minix_aops;
	} else
		init_special_inode(inode, inode->i_mode, rdev);
}

/*
 * The minix V1 function to read an inode.
 */
static struct inode *V1_minix_iget(struct inode *inode)
{
	printk("V1_minix_iget\n");
	
	struct buffer_head * bh;
	struct minix_inode * raw_inode;
	struct minix_inode_info *minix_inode = minix_i(inode);
	int i;

	raw_inode = minix_V1_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode) {
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}
	inode->i_mode = raw_inode->i_mode;
	i_uid_write(inode, raw_inode->i_uid);
	i_gid_write(inode, raw_inode->i_gid);
	set_nlink(inode, raw_inode->i_nlinks);
	inode->i_size = raw_inode->i_size;
	inode->i_mtime.tv_sec = inode->i_atime.tv_sec = inode->i_ctime.tv_sec = raw_inode->i_time;
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	inode->i_blocks = 0;
	for (i = 0; i < 9; i++)
		minix_inode->u.i1_data[i] = raw_inode->i_zone[i];
	minix_set_inode(inode, old_decode_dev(raw_inode->i_zone[0]));
	brelse(bh);
	unlock_new_inode(inode);
	return inode;
}

/*
 * The minix V2 function to read an inode.
 */
static struct inode *V2_minix_iget(struct inode *inode)
{
	printk("V2_minix_iget\n");
	
	struct buffer_head * bh;
	struct minix2_inode * raw_inode;
	struct minix_inode_info *minix_inode = minix_i(inode);
	int i;

	raw_inode = minix_V2_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode) {
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}
	inode->i_mode = raw_inode->i_mode;
	i_uid_write(inode, raw_inode->i_uid);
	i_gid_write(inode, raw_inode->i_gid);
	set_nlink(inode, raw_inode->i_nlinks);
	inode->i_size = raw_inode->i_size;
	inode->i_mtime.tv_sec = raw_inode->i_mtime;
	inode->i_atime.tv_sec = raw_inode->i_atime;
	inode->i_ctime.tv_sec = raw_inode->i_ctime;
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	inode->i_blocks = 0;
	for (i = 0; i < 10; i++)
		minix_inode->u.i2_data[i] = raw_inode->i_zone[i];
	minix_set_inode(inode, old_decode_dev(raw_inode->i_zone[0]));
	brelse(bh);
	unlock_new_inode(inode);
	return inode;
}

/*
 * The global function to read an inode.
 */
struct inode *minix_iget(struct super_block *sb, unsigned long ino)
{
	printk("minix_iget\n");
	
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	if (INODE_VERSION(inode) == MINIX_V1)
		return V1_minix_iget(inode);
	else
		return V2_minix_iget(inode);
}

/*
 * The minix V1 function to synchronize an inode.
 */
static struct buffer_head * V1_minix_update_inode(struct inode * inode)
{
	printk("V1_minix_update_inode\n");
	
	struct buffer_head * bh;
	struct minix_inode * raw_inode;
	struct minix_inode_info *minix_inode = minix_i(inode);
	int i;

	raw_inode = minix_V1_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode)
		return NULL;
		
	raw_inode->i_mode = inode->i_mode;
	raw_inode->i_uid = fs_high2lowuid(i_uid_read(inode));
	raw_inode->i_gid = fs_high2lowgid(i_gid_read(inode));
	raw_inode->i_nlinks = inode->i_nlink;
	raw_inode->i_size = inode->i_size;
	raw_inode->i_time = inode->i_mtime.tv_sec;
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		raw_inode->i_zone[0] = old_encode_dev(inode->i_rdev);
	else for (i = 0; i < 9; i++)
		raw_inode->i_zone[i] = minix_inode->u.i1_data[i];
	mark_buffer_dirty(bh);
	
	return bh;
}

/*
 * The minix V2 function to synchronize an inode.
 */
static struct buffer_head * V2_minix_update_inode(struct inode * inode)
{
	printk("V2_minix_update_inode\n");

	struct buffer_head * bh;
	struct minix2_inode * raw_inode;
	struct minix_inode_info *minix_inode = minix_i(inode);
	int i;

	raw_inode = minix_V2_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode)
		return NULL;
	raw_inode->i_mode = inode->i_mode;
	raw_inode->i_uid = fs_high2lowuid(i_uid_read(inode));
	raw_inode->i_gid = fs_high2lowgid(i_gid_read(inode));
	raw_inode->i_nlinks = inode->i_nlink;
	raw_inode->i_size = inode->i_size;
	raw_inode->i_mtime = inode->i_mtime.tv_sec;
	raw_inode->i_atime = inode->i_atime.tv_sec;
	raw_inode->i_ctime = inode->i_ctime.tv_sec;
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		raw_inode->i_zone[0] = old_encode_dev(inode->i_rdev);
	else for (i = 0; i < 10; i++)
		raw_inode->i_zone[i] = minix_inode->u.i2_data[i];
	mark_buffer_dirty(bh);
	return bh;
}

static int minix_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	printk("minix_write_inode\n");

	int err = 0;
	struct buffer_head *bh;

	if (INODE_VERSION(inode) == MINIX_V1)
		bh = V1_minix_update_inode(inode);
	else
		bh = V2_minix_update_inode(inode);
	if (!bh)
		return -EIO;
	
	//dump_buffer(bh->b_data, bh->b_size);
	
	if (wbc->sync_mode == WB_SYNC_ALL && buffer_dirty(bh)) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh)) {
			printk("IO error syncing minix inode [%s:%08lx]\n",
				inode->i_sb->s_id, inode->i_ino);
			err = -EIO;
		}
	}
	
	brelse (bh);	
	
	return err;
}

int minix_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	printk("minix_getattr\n");

	struct super_block *sb = dentry->d_sb;
	generic_fillattr(d_inode(dentry), stat);
	if (INODE_VERSION(d_inode(dentry)) == MINIX_V1)
		stat->blocks = (BLOCK_SIZE / 512) * V1_minix_blocks(stat->size, sb);
	else
		stat->blocks = (sb->s_blocksize / 512) * V2_minix_blocks(stat->size, sb);
	stat->blksize = sb->s_blocksize;
	return 0;
}

/*
 * The function that is called for file truncation.
 */
void minix_truncate(struct inode * inode)
{
	printk("minix_truncate\n");
	
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)))
		return;
	if (INODE_VERSION(inode) == MINIX_V1)
		V1_minix_truncate(inode);
	else
		V2_minix_truncate(inode);
}

static struct dentry *minix_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	printk("mount_bdev\n");
	
	return mount_bdev(fs_type, flags, dev_name, data, minix_fill_super);
}

static struct file_system_type minix_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "minix",
	.mount		= minix_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("xminix");

static int __init init_minix_fs(void)
{
	printk(KERN_INFO"xminixfs init");
	int err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&minix_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_minix_fs(void)
{
	printk(KERN_INFO"xminixfs exit");
        unregister_filesystem(&minix_fs_type);
	destroy_inodecache();
}

module_init(init_minix_fs)
module_exit(exit_minix_fs)
MODULE_LICENSE("GPL");

