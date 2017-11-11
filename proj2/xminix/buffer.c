/*
 *  reconstrução de procedimentos de leitura e escrita em disco
 */

#include "xminix.h"
#include "security.h"

/*
 * =========================================================================
 *                                   MISC
 * =========================================================================
 */

/*
 * função auxiliar para printar os caracteres printaveis de um buffer
 */ 
void dump_buffer(unsigned char *buf, size_t size)
{
	if (!buf) {
		return printk("dump_buffer null pointer\n");
	}
	
	printk("size: %d %x\n", size, buf);
	
	size_t i; 
	for (i = 0; i < size; i++) {
		char c = (char)buf[i];		
		if (c != '\0' && c != '\n' && (c == 9 || c == 10 || (c >= 32 && c <= 127))) {
			printk("%c", (char)c);
		}
		/*else {
			printk("\\x%02x", (unsigned char)c);
		}*/		
	}	
	printk("\n");
}

/*
 * =========================================================================
 *                               KERNEL MISC
 * =========================================================================
 */
 
static void buffer_io_error(struct buffer_head *bh, char *msg)
{
	char b[BDEVNAME_SIZE];

	if (!test_bit(BH_Quiet, &bh->b_state))
		//printk_ratelimited(KERN_ERR // removido para simplificar reconstrucao
		printk(KERN_ERR
			"Buffer I/O error on dev %s, logical block %llu%s\n",
			bdevname(bh->b_bdev, b),
			(unsigned long long)bh->b_blocknr, msg);
}

static inline int block_size_bits(unsigned int blocksize)
{
	return ilog2(blocksize);
}

static struct buffer_head *create_page_buffers(struct page *page, struct inode *inode, unsigned int b_state)
{
	BUG_ON(!PageLocked(page));

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << ACCESS_ONCE(inode->i_blkbits), b_state);
	return page_buffers(page);
}

/*
 * =========================================================================
 *                                   READ
 * =========================================================================
 */
 

/* 
 * nao esquecer de limpar o buffer para testar:
 * free && sync && echo 3 > /proc/sys/vm/drop_caches && free
 */
 
static void xminix_end_bio_bh_io_sync(struct bio *bio)
{
	printk("xminix_end_bio_bh_io_sync\n");			
	
	struct buffer_head *bh = bio->bi_private;

	if (unlikely(bio_flagged(bio, BIO_QUIET)))
		set_bit(BH_Quiet, &bh->b_state);
		
	bh->b_end_io(bh, !bio->bi_error);
	
	bio_put(bio);
}

static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
	printk("end_buffer_async_read\n");
	
	unsigned long flags;
	struct buffer_head *first;
	struct buffer_head *tmp;
	struct page *page;
	int page_uptodate = 1;
	
	BUG_ON(!buffer_async_read(bh));
	
	page = bh->b_page;
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		clear_buffer_uptodate(bh);
		buffer_io_error(bh, ", async page read");
		SetPageError(page);
	}	
		
	/*
	 * Be _very_ careful from here on. Bad things can happen if
	 * two buffer heads end IO at almost the same time and both
	 * decide that the page is now completely done.
	 */
	first = page_buffers(page);
	local_irq_save(flags);
	bit_spin_lock(BH_Uptodate_Lock, &first->b_state);
	
	///////////////////////////////////////////////////////////////////////////
	// insira descriptografia aqui	
	printk("[READ] Antes Descriptografia ");			
	dump_buffer(bh->b_data, bh->b_size);
	
	printk("TODO DECRYPT\n");
	//aes_operation(AES_DECRYPT, bh->b_data, bh->b_size);
	//memset(bh->b_data, '1', bh->b_size);
	
	printk("[READ] Depois Descriptografia ");			
	dump_buffer(bh->b_data, bh->b_size);
	///////////////////////////////////////////////////////////////////////////	
	
	clear_buffer_async_read(bh);
	
	unlock_buffer(bh);
			
	tmp = bh;
	do {
		if (!buffer_uptodate(tmp))
			page_uptodate = 0;
		if (buffer_async_read(tmp)) {
			BUG_ON(!buffer_locked(tmp));
			goto still_busy;
		}
				
		tmp = tmp->b_this_page;
	} while (tmp != bh);
		
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);	
		
	/*
	 * If none of the buffers had errors and they are all
	 * uptodate then we can set the page uptodate.
	 */
	if (page_uptodate && !PageError(page))
		SetPageUptodate(page);
	unlock_page(page);
		
	return;

still_busy:
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);
	return;
}

static void mark_buffer_async_read(struct buffer_head *bh)
{	
	bh->b_end_io = end_buffer_async_read;
	set_buffer_async_read(bh);
}

static void guard_bio_eod(int rw, struct bio *bio)
{
	sector_t maxsector;
	struct bio_vec *bvec = &bio->bi_io_vec[bio->bi_vcnt - 1];
	unsigned truncated_bytes;

	maxsector = i_size_read(bio->bi_bdev->bd_inode) >> 9;
	if (!maxsector)
		return;

	/*
	 * If the *whole* IO is past the end of the device,
	 * let it through, and the IO layer will turn it into
	 * an EIO.
	 */
	if (unlikely(bio->bi_iter.bi_sector >= maxsector))
		return;

	maxsector -= bio->bi_iter.bi_sector;
	if (likely((bio->bi_iter.bi_size >> 9) <= maxsector))
		return;

	/* Uhhuh. We've got a bio that straddles the device size! */
	truncated_bytes = bio->bi_iter.bi_size - (maxsector << 9);

	/* Truncate the bio.. */
	bio->bi_iter.bi_size -= truncated_bytes;
	bvec->bv_len -= truncated_bytes;

	/* ..and clear the end of the buffer for reads */
	if ((rw & RW_MASK) == READ) {
		zero_user(bvec->bv_page, bvec->bv_offset + bvec->bv_len,
				truncated_bytes);
	}
}

static int xminix_submit_bh_wbc(int rw, struct buffer_head *bh,
			 unsigned long bio_flags, struct writeback_control *wbc)
{
	struct bio *bio;

	BUG_ON(!buffer_locked(bh));
	BUG_ON(!buffer_mapped(bh));
	BUG_ON(!bh->b_end_io);
	BUG_ON(buffer_delay(bh));
	BUG_ON(buffer_unwritten(bh));

	/*
	 * Only clear out a write error when rewriting
	 */
	if (test_set_buffer_req(bh) && (rw & WRITE))
		clear_buffer_write_io_error(bh);

	/*
	 * from here on down, it's all bio -- do the initial mapping,
	 * submit_bio -> generic_make_request may further map this bio around
	 */
	bio = bio_alloc(GFP_NOIO, 1);

	if (wbc) {
		wbc_init_bio(wbc, bio);
		wbc_account_io(wbc, bh->b_page, bh->b_size);
	}

	bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	bio->bi_bdev = bh->b_bdev;

	bio_add_page(bio, bh->b_page, bh->b_size, bh_offset(bh));
	BUG_ON(bio->bi_iter.bi_size != bh->b_size);

	bio->bi_end_io = xminix_end_bio_bh_io_sync;
	bio->bi_private = bh;
	bio->bi_flags |= bio_flags;

	/* Take care of bh's that straddle the end of the device */
	guard_bio_eod(rw, bio);

	if (buffer_meta(bh))
		rw |= REQ_META;
	if (buffer_prio(bh))
		rw |= REQ_PRIO;

	submit_bio(rw, bio);
	return 0;
}

static int xminix_submit_bh(int rw, struct buffer_head *bh)
{
	return xminix_submit_bh_wbc(rw, bh, 0, NULL);
}

int xminix_block_read_full_page(struct page *page, get_block_t *get_block)
{
	struct inode *inode = page->mapping->host;
	sector_t iblock, lblock;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize, bbits;
	int nr, i;
	int fully_mapped = 1;

	head = create_page_buffers(page, inode, 0);
	blocksize = head->b_size;
	bbits = block_size_bits(blocksize);

	iblock = (sector_t)page->index << (PAGE_CACHE_SHIFT - bbits);
	lblock = (i_size_read(inode)+blocksize-1) >> bbits;
	bh = head;
	nr = 0;
	i = 0;

	do {		
		if (buffer_uptodate(bh))
			continue;

		if (!buffer_mapped(bh)) {
			int err = 0;

			fully_mapped = 0;
			if (iblock < lblock) {
				WARN_ON(bh->b_size != blocksize);
				err = get_block(inode, iblock, bh, 0);
				if (err)
					SetPageError(page);
			}
			if (!buffer_mapped(bh)) {
				zero_user(page, i * blocksize, blocksize);
				if (!err)
					set_buffer_uptodate(bh);
				continue;
			}			
			
			/*
			 * get_block() might have updated the buffer
			 * synchronously
			 */
			if (buffer_uptodate(bh))
				continue;
		}
		arr[nr++] = bh;
	} while (i++, iblock++, (bh = bh->b_this_page) != head);

	if (fully_mapped)
		SetPageMappedToDisk(page);

	if (!nr) {
		/*
		 * All buffers are uptodate - we can set the page uptodate
		 * as well. But not if get_block() returned an error.
		 */
		if (!PageError(page))
			SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	/* Stage two: lock the buffers */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		lock_buffer(bh);
		mark_buffer_async_read(bh);
	}

	/*
	 * Stage 3: start the IO.  Check for uptodateness
	 * inside the buffer lock in case another process reading
	 * the underlying blockdev brought it uptodate (the sct fix).
	 */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		
		if (buffer_uptodate(bh))
			end_buffer_async_read(bh, 1);	
		else
			xminix_submit_bh(READ, bh);		
	}
	return 0;
}



/*
 * =========================================================================
 *                                  WRITE
 * =========================================================================
 */
 
static int xminix__block_write_begin(struct page *page, loff_t pos, unsigned len,
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

int xminix_block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
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

/*
 * reconstruimos no modulo o generic_write_end e suas principais funções que permitem 
 * chegar ao __block_commit_write, onde podemos obter o tamanho do bloco, a quantidade
 * de blocos que vamos escrever, o tamanho dos dados e conseguimos alterar os dados
 * para possibilitar a criptografia.
 */ 
static int xminix__block_commit_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to)
{
	printk("xminix__block_commit_write\n");
	
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
			////////////////////////////////////////////////////////
			//insira criptografia aqui
			printk("[WRITE] Antes criptografia ");			
			dump_buffer(bh->b_data, blocksize);
					
			aes_operation(AES_ENCRYPT, bh->b_data, bh->b_size);
			
			printk("[WRITE] Depois criptografia ");
			dump_buffer(bh->b_data, blocksize);	
			////////////////////////////////////////////////////////	
			
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

