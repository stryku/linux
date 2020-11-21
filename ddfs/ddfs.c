#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/kernel.h>
#include <linux/iversion.h>
#include <linux/writeback.h>

#define DDFS_SUPER_MAGIC 0xddf5
#define DDFS_CLUSTER_UNUSED 0
#define DDFS_CLUSTER_EOF 0xffffffff

#define DDFS_PART_NAME 1
#define DDFS_PART_ATTRIBUTES 2
#define DDFS_PART_SIZE 4
#define DDFS_PART_FIRST_CLUSTER 8

#define DDFS_ROOT_INO 0

#define DDFS_FILE_ATTR 1
#define DDFS_DIR_ATTR 2

#define DDFS_DEFAULT_MODE ((umode_t)(S_IRUGO | S_IWUGO | S_IXUGO))

#define dd_print(...)                                                          \
	do {                                                                   \
		printk(KERN_INFO "-------------------[DDFS]: " __VA_ARGS__);   \
	} while (0);

#define dd_error(...)                                                          \
	do {                                                                   \
		printk(KERN_ERR                                                \
		       "-------------------[DDFS ERR]: " __VA_ARGS__);         \
	} while (0);

MODULE_LICENSE("Dual BSD/GPL");

/*
 * DDFS inode data in memory
 */
struct ddfs_inode_info {
	unsigned dentry_index; //
	unsigned number_of_entries;

	// fat stuff:
	spinlock_t cache_lru_lock;
	struct list_head cache_lru;
	int nr_caches;
	/* for avoiding the race between fat_free() and fat_get_cluster() */
	unsigned int cache_valid_id;

	/* NOTE: mmu_private is 64bits, so must hold ->i_mutex to access */
	loff_t mmu_private; /* physically allocated size */

	int i_start; /* first cluster or 0 */
	int i_logstart; /* logical first cluster */
	int i_attrs; /* unused attribute bits */
	loff_t i_pos; /* on-disk position of directory entry or 0 */
	struct hlist_node i_fat_hash; /* hash by i_location */
	struct hlist_node i_dir_hash; /* hash by i_logstart */
	struct rw_semaphore truncate_lock; /* protect bmap against truncate */
	struct inode ddfs_inode; // Todo: Should be named vfs_inode
};

void dump_ddfs_inode_info(struct ddfs_inode_info *info)
{
	dd_print("dump_ddfs_inode_info, info: %p", info);
	dd_print("\t\tinfo->dentry_index: %u", info->dentry_index);
	dd_print("\t\tinfo->number_of_entries: %u", info->number_of_entries);
	dd_print("\t\tinfo->i_start: %d", info->i_start);
	dd_print("\t\tinfo->i_logstart: %d", info->i_logstart);
	dd_print("\t\tinfo->i_attrs: %d", info->i_attrs);
	dd_print("\t\tinfo->i_pos: %llu", info->i_pos);
}

#define DDFS_DIR_ENTRY_NAME_TYPE __u8
#define DDFS_DIR_ENTRY_ATTRIBUTES_TYPE __u8
#define DDFS_DIR_ENTRY_SIZE_TYPE __u64
#define DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE __u32

struct ddfs_dir_entry {
	unsigned entry_index;
#define DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE 4
	DDFS_DIR_ENTRY_NAME_TYPE name[DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE];
	DDFS_DIR_ENTRY_ATTRIBUTES_TYPE attributes;
	DDFS_DIR_ENTRY_SIZE_TYPE size;
	DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE first_cluster;
};

static inline void dump_ddfs_dir_entry(const struct ddfs_dir_entry *entry)
{
	dd_print("dump_ddfs_dir_entry: %p", entry);

	dd_print("\t\tentry->entry_index %u", entry->entry_index);
	dd_print("\t\tentry->name %s", entry->name);
	dd_print("\t\tentry->attributes %u", (unsigned)entry->attributes);
	dd_print("\t\tentry->size %lu", entry->size);
	dd_print("\t\tentry->first_cluster %u", (unsigned)entry->first_cluster);
}

static inline struct ddfs_inode_info *DDFS_I(struct inode *inode)
{
	return container_of(inode, struct ddfs_inode_info, ddfs_inode);
}

struct ddfs_sb_info {
	unsigned int table_offset; // From begin of partition
	unsigned int table_size; // In bytes
	unsigned int number_of_table_entries;

	unsigned int cluster_size; // In bytes

	unsigned int data_offset; // From begin of partition
	unsigned int data_cluster_no; // Data first cluster no

	unsigned int root_cluster; //First cluster of root dir.

	unsigned long block_size; // Size of block (sector) in bytes
	unsigned int blocks_per_cluster; // Number of blocks (sectors) per cluster

	unsigned int entries_per_cluster; // Dir entries per cluster

	unsigned int name_entries_offset;
	unsigned int attributes_entries_offset;
	unsigned int size_entries_offset;
	unsigned int first_cluster_entries_offset;

	struct mutex table_lock;
	struct mutex s_lock;
	struct mutex build_inode_lock;

	const void *dir_ops; /* Opaque; default directory operations */
};

static inline struct ddfs_sb_info *DDFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

struct dir_entry_part_offsets {
	unsigned block_on_device;
	unsigned offset_on_block;
};

struct dir_entry_offsets {
	/*
	entry index
	block on device
	offset on block
	*/

	unsigned entry_index;

	struct dir_entry_part_offsets name;
	struct dir_entry_part_offsets attributes;
	struct dir_entry_part_offsets size;
	struct dir_entry_part_offsets first_cluster;
};

void dump_dir_entry_offsets(struct dir_entry_offsets *offsets)
{
	dd_print("dump_dir_entry_offsets: %p", offsets);

	dd_print("\t\toffsets->name.block_on_device: %u",
		 offsets->name.block_on_device);
	dd_print("\t\toffsets->name.offset_on_block: %u",
		 offsets->name.offset_on_block);

	dd_print("\t\toffsets->attributes.block_on_device: %u",
		 offsets->attributes.block_on_device);
	dd_print("\t\toffsets->attributes.offset_on_block: %u",
		 offsets->attributes.offset_on_block);

	dd_print("\t\toffsets->size.block_on_device: %u",
		 offsets->size.block_on_device);
	dd_print("\t\toffsets->size.offset_on_block: %u",
		 offsets->size.offset_on_block);

	dd_print("\t\toffsets->first_cluster.block_on_device: %u",
		 offsets->first_cluster.block_on_device);
	dd_print("\t\toffsets->first_cluster.offset_on_block: %u",
		 offsets->first_cluster.offset_on_block);
}

static inline struct dir_entry_part_offsets
calc_dir_entry_part_offsets(struct inode *dir, unsigned entry_index,
			    unsigned entries_offset_on_cluster,
			    unsigned entry_part_size)
{
	struct super_block *sb = dir->i_sb;
	struct ddfs_sb_info *sbi = DDFS_SB(sb);
	const struct ddfs_inode_info *dd_idir = DDFS_I(dir);

	const unsigned entry_index_on_cluster =
		entry_index % sbi->entries_per_cluster;

	// Logical cluster no on which the entry lays
	const unsigned entry_logic_cluster_no =
		dd_idir->i_logstart + (entry_index / sbi->entries_per_cluster);

	// The entry part offset on cluster. In bytes.
	const unsigned offset_on_cluster =
		entries_offset_on_cluster +
		entry_index_on_cluster * entry_part_size;

	// The entry part block on cluster
	const unsigned entry_part_block_no_on_logic_cluster =
		offset_on_cluster / sb->s_blocksize;

	// The entry part block no on device.
	const unsigned entry_part_block_no_on_device =
		(sbi->data_cluster_no + entry_logic_cluster_no) *
			sbi->blocks_per_cluster +
		entry_part_block_no_on_logic_cluster;

	// The entry part offset on block. In bytes.
	const unsigned entry_part_offset_on_block =
		offset_on_cluster % sb->s_blocksize;

	const struct dir_entry_part_offsets result = {
		.block_on_device = entry_part_block_no_on_device,
		.offset_on_block = entry_part_offset_on_block
	};

	return result;
}

struct dir_entry_offsets calc_dir_entry_offsets(struct inode *dir,
						unsigned entry_index)
{
	struct super_block *sb = dir->i_sb;
	struct ddfs_sb_info *sbi = DDFS_SB(sb);

	const struct dir_entry_offsets result = {
		.entry_index = entry_index,

		.name = calc_dir_entry_part_offsets(
			dir, entry_index, sbi->name_entries_offset,
			sizeof(DDFS_DIR_ENTRY_NAME_TYPE) *
				DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE),

		.attributes = calc_dir_entry_part_offsets(
			dir, entry_index, sbi->attributes_entries_offset,
			sizeof(DDFS_DIR_ENTRY_ATTRIBUTES_TYPE)),

		.size = calc_dir_entry_part_offsets(
			dir, entry_index, sbi->size_entries_offset,
			sizeof(DDFS_DIR_ENTRY_SIZE_TYPE)),

		.first_cluster = calc_dir_entry_part_offsets(
			dir, entry_index, sbi->first_cluster_entries_offset,
			sizeof(DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE))
	};

	return result;
}

struct dir_entry_ptrs {
	long error;

	struct {
		DDFS_DIR_ENTRY_NAME_TYPE *ptr;
		struct buffer_head *bh;
	} name;

	struct {
		DDFS_DIR_ENTRY_ATTRIBUTES_TYPE *ptr;
		struct buffer_head *bh;
	} attributes;

	struct {
		DDFS_DIR_ENTRY_SIZE_TYPE *ptr;
		struct buffer_head *bh;
	} size;

	struct {
		DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE *ptr;
		struct buffer_head *bh;
	} first_cluster;
};

void dump_dir_entry_ptrs(const struct dir_entry_ptrs *ptrs)
{
	dd_print("dump_dir_entry_ptrs: %p", ptrs);
	dd_print("\t\tptrs->error: %ld", ptrs->error);
	dd_print("\t\tptrs->name.ptr: %p", ptrs->name.ptr);
	dd_print("\t\tptrs->name.bh: %p", ptrs->name.bh);

	dd_print("\t\tptrs->attributes.ptr: %p", ptrs->attributes.ptr);
	dd_print("\t\tptrs->attributes.bh: %p", ptrs->attributes.bh);

	dd_print("\t\tptrs->size.ptr: %p", ptrs->size.ptr);
	dd_print("\t\tptrs->size.bh: %p", ptrs->size.bh);

	dd_print("\t\tptrs->first_cluster.ptr: %p", ptrs->first_cluster.ptr);
	dd_print("\t\tptrs->first_cluster.bh: %p", ptrs->first_cluster.bh);
}

static inline struct dir_entry_ptrs
access_dir_entries(struct inode *dir, unsigned entry_index, unsigned part_flags)
{
	const struct dir_entry_offsets offsets =
		calc_dir_entry_offsets(dir, entry_index);
	struct super_block *sb = dir->i_sb;
	struct dir_entry_ptrs result;

	struct buffer_head *hydra[4] = { NULL };
	unsigned block_no[4] = { 0 };
	unsigned counter = 0;

	struct part_data {
		unsigned flag;
		const struct dir_entry_part_offsets *offsets;
		struct buffer_head **dest_bh;
		void **dest_ptr;
	};

	void *result_name_ptr = &result.name.ptr;
	void *result_attributes_ptr = &result.attributes.ptr;
	void *result_size_ptr = &result.size.ptr;
	void *result_first_cluster_ptr = &result.first_cluster.ptr;

	struct part_data parts_data[] = {
		{ .flag = DDFS_PART_NAME,
		  .offsets = &offsets.name,
		  .dest_bh = &result.name.bh,
		  .dest_ptr = &result_name_ptr },
		{ .flag = DDFS_PART_ATTRIBUTES,
		  .offsets = &offsets.attributes,
		  .dest_bh = &result.attributes.bh,
		  .dest_ptr = &result_attributes_ptr },
		{ .flag = DDFS_PART_SIZE,
		  .offsets = &offsets.size,
		  .dest_bh = &result.size.bh,
		  .dest_ptr = &result_size_ptr },
		{ .flag = DDFS_PART_FIRST_CLUSTER,
		  .offsets = &offsets.first_cluster,
		  .dest_bh = &result.first_cluster.bh,
		  .dest_ptr = &result_first_cluster_ptr }
	};

	unsigned number_of_parts = sizeof(parts_data) / sizeof(parts_data[0]);
	int i;

	for (i = 0; i < number_of_parts; ++i) {
		struct part_data data = parts_data[i];
		int used_cached = 0;
		int j;
		struct buffer_head *bh;

		if (!(part_flags & data.flag)) {
			*data.dest_bh = NULL;
			continue;
		}

		for (j = 0; j < counter; ++j) {
			// char *ptr;

			if (block_no[j] != data.offsets->block_on_device) {
				continue;
			}

			// The same block no as cached one. Reuse it.

			used_cached = 1;
			*data.dest_bh = hydra[j];
			// ptr = (char *)(hydra[j]->b_data) +
			//       data.offsets->offset_on_block;
			// *data.dest_ptr = ptr;
			break;
		}

		if (used_cached) {
			continue;
		}

		// No cached bh. Need to read
		bh = sb_bread(sb, data.offsets->block_on_device);
		if (!bh) {
			*data.dest_bh = NULL;
			continue;
		}

		// char *ptr =
		// 	(char *)(bh->b_data) + data.offsets->offset_on_block;
		// *data.dest_ptr = ptr;
		*data.dest_bh = bh;

		hydra[counter] = bh;
		block_no[counter] = data.offsets->block_on_device;
		++counter;
	}

	result.error = 0;

	if (result.name.bh) {
		unsigned char *ptr =
			result.name.bh->b_data + offsets.name.offset_on_block;
		result.name.ptr = (DDFS_DIR_ENTRY_NAME_TYPE *)ptr;
	}

	if (result.attributes.bh) {
		unsigned char *ptr = result.attributes.bh->b_data +
				     offsets.attributes.offset_on_block;
		result.attributes.ptr = (DDFS_DIR_ENTRY_ATTRIBUTES_TYPE *)ptr;
	}

	if (result.size.bh) {
		unsigned char *ptr =
			result.size.bh->b_data + offsets.size.offset_on_block;
		result.size.ptr = (DDFS_DIR_ENTRY_SIZE_TYPE *)ptr;
	}

	if (result.first_cluster.bh) {
		unsigned char *ptr = result.first_cluster.bh->b_data +
				     offsets.first_cluster.offset_on_block;
		result.first_cluster.ptr =
			(DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE *)ptr;
	}

	dd_print("access_dir_entries: dir: %p, entry_index: %d, part_flags: %u",
		 dir, entry_index, part_flags);

	return result;
}

static inline void release_dir_entries(const struct dir_entry_ptrs *ptrs,
				       unsigned part_flags)
{
	dd_print("release_dir_entries: ptrs: %p, part_flags: %u", ptrs,
		 part_flags);
	dump_dir_entry_ptrs(ptrs);

	if (part_flags & DDFS_PART_NAME && ptrs->name.bh) {
		brelse(ptrs->name.bh);
	}
	if (part_flags & DDFS_PART_ATTRIBUTES && ptrs->attributes.bh) {
		brelse(ptrs->attributes.bh);
	}
	if (part_flags & DDFS_PART_SIZE && ptrs->size.bh) {
		brelse(ptrs->size.bh);
	}
	if (part_flags & DDFS_PART_FIRST_CLUSTER && ptrs->first_cluster.bh) {
		brelse(ptrs->first_cluster.bh);
	}
}

static struct kmem_cache *ddfs_inode_cachep;

static struct inode *ddfs_alloc_inode(struct super_block *sb)
{
	struct ddfs_inode_info *ei;
	dd_print("ddfs_alloc_inode");
	dd_print("calling kmem_cache_alloc");
	ei = kmem_cache_alloc(ddfs_inode_cachep, GFP_NOFS);
	if (!ei) {
		dd_print("kmem_cache_alloc failed");
		dd_print("~ddfs_alloc_inode NULL");
		return NULL;
	}

	dd_print("kmem_cache_alloc succeed");

	dd_print("calling init_rwsem");
	init_rwsem(&ei->truncate_lock);

	dd_print("~ddfs_alloc_inode %p", &ei->ddfs_inode);
	return &ei->ddfs_inode;
}

static void ddfs_free_inode(struct inode *inode)
{
	kmem_cache_free(ddfs_inode_cachep, DDFS_I(inode));
}

// static inline loff_t ddfs_i_pos_read(struct ddfs_sb_info *sbi,
// 				     struct inode *inode)
// {
// 	return DDFS_I(inode)->i_pos;
// 	// 	loff_t i_pos;
// 	// #if BITS_PER_LONG == 32
// 	// 	spin_lock(&sbi->inode_hash_lock);
// 	// #endif
// 	// 	i_pos = DDFS_I(inode)->i_pos;
// 	// #if BITS_PER_LONG == 32
// 	// 	spin_unlock(&sbi->inode_hash_lock);
// 	// #endif
// 	// 	return i_pos;
// }

/* Convert linear UNIX date to a FAT time/date pair. */
void fat_time_unix2fat(struct ddfs_sb_info *sbi, struct timespec64 *ts,
		       __le16 *time, __le16 *date, u8 *time_cs)
{
	struct tm tm;
	// time64_to_tm(ts->tv_sec, -fat_tz_offset(sbi), &tm);
	time64_to_tm(ts->tv_sec, 0, &tm);

	/*  FAT can only support year between 1980 to 2107 */
	if (tm.tm_year < 1980 - 1900) {
		*time = 0;
		*date = cpu_to_le16((0 << 9) | (1 << 5) | 1);
		if (time_cs)
			*time_cs = 0;
		return;
	}
	if (tm.tm_year > 2107 - 1900) {
		*time = cpu_to_le16((23 << 11) | (59 << 5) | 29);
		*date = cpu_to_le16((127 << 9) | (12 << 5) | 31);
		if (time_cs)
			*time_cs = 199;
		return;
	}

	/* from 1900 -> from 1980 */
	tm.tm_year -= 80;
	/* 0~11 -> 1~12 */
	tm.tm_mon++;
	/* 0~59 -> 0~29(2sec counts) */
	tm.tm_sec >>= 1;

	*time = cpu_to_le16(tm.tm_hour << 11 | tm.tm_min << 5 | tm.tm_sec);
	*date = cpu_to_le16(tm.tm_year << 9 | tm.tm_mon << 5 | tm.tm_mday);
	if (time_cs)
		*time_cs = (ts->tv_sec & 1) * 100 + ts->tv_nsec / 10000000;
}

static inline void ddfs_get_blknr_offset(struct ddfs_sb_info *sbi, loff_t i_pos,
					 sector_t *blknr, int *offset)
{
	*blknr = i_pos / sbi->block_size;
	*offset = i_pos % sbi->block_size;
}

static int __ddfs_write_inode(struct inode *inode, int wait)
{
	struct super_block *sb = inode->i_sb;
	struct ddfs_sb_info *sbi = DDFS_SB(sb);
	struct buffer_head *bh;
	struct ddfs_inode_info *dd_inode = DDFS_I(inode);
	loff_t i_pos;
	sector_t blocknr;
	int offset;

retry:
	// i_pos = ddfs_i_pos_read(sbi, inode);
	i_pos = dd_inode->i_pos;
	if (!i_pos) {
		return 0;
	}

	ddfs_get_blknr_offset(sbi, i_pos, &blocknr, &offset);
	bh = sb_bread(sb, blocknr);
	if (!bh) {
		dd_error("unable to read inode block for updating (i_pos %lld)",
			 i_pos);
		return -EIO;
	}

	// Todo: do we need it?
	// spin_lock(&sbi->inode_hash_lock);
	if (i_pos != dd_inode->i_pos) {
		// spin_unlock(&sbi->inode_hash_lock);
		brelse(bh);
		goto retry;
	}

	// Todo check whether entry index is inside cluster

	{
		const unsigned part_flags = DDFS_PART_ATTRIBUTES |
					    DDFS_PART_SIZE |
					    DDFS_PART_FIRST_CLUSTER;
		struct dir_entry_ptrs entry_ptrs = access_dir_entries(
			inode, dd_inode->dentry_index, part_flags);

		*entry_ptrs.first_cluster.ptr = dd_inode->i_logstart;
		*entry_ptrs.size.ptr = inode->i_size;
		*entry_ptrs.attributes.ptr = DDFS_FILE_ATTR;

		mark_buffer_dirty(entry_ptrs.first_cluster.bh);
		mark_buffer_dirty(entry_ptrs.size.bh);
		mark_buffer_dirty(entry_ptrs.attributes.bh);
		if (wait) {
			// Todo: handle
			// err = sync_dirty_buffer(bh);
		}

		release_dir_entries(&entry_ptrs, part_flags);
	}

	return 0;
}

static int ddfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return __ddfs_write_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
}

int ddfs_sync_inode(struct inode *inode)
{
	return __ddfs_write_inode(inode, 1);
}

static inline void lock_table(struct ddfs_sb_info *sbi)
{
	mutex_lock(&sbi->table_lock);
}

static inline void unlock_table(struct ddfs_sb_info *sbi)
{
	mutex_unlock(&sbi->table_lock);
}

static inline void lock_data(struct ddfs_sb_info *sbi)
{
	mutex_lock(&sbi->s_lock);
}

static inline void unlock_data(struct ddfs_sb_info *sbi)
{
	mutex_unlock(&sbi->s_lock);
}

static inline void lock_inode_build(struct ddfs_sb_info *sbi)
{
	mutex_lock(&sbi->build_inode_lock);
}

static inline void unlock_inode_build(struct ddfs_sb_info *sbi)
{
	mutex_unlock(&sbi->build_inode_lock);
}

static inline void table_write_cluster(struct ddfs_sb_info *sbi,
				       unsigned cluster_no,
				       unsigned cluster_value)
{
}

/* Free all clusters after the skip'th cluster. */
static int ddfs_free(struct inode *inode, int skip)
{
	struct super_block *sb = inode->i_sb;
	struct ddfs_sb_info *sbi = DDFS_SB(sb);
	int err, wait, free_start, i_start, i_logstart;
	struct ddfs_inode_info *dd_inode = DDFS_I(inode);
	struct buffer_head *bh;

	if (dd_inode->i_start == 0)
		return 0;

	// fat_cache_inval_inode(inode);

	wait = IS_DIRSYNC(inode);
	i_start = free_start = dd_inode->i_start;
	i_logstart = dd_inode->i_logstart;

	/* First, we write the new file size. */
	if (!skip) {
		dd_inode->i_start = 0;
		dd_inode->i_logstart = 0;
	}
	// dd_inode->i_attrs |= ATTR_ARCH;
	// fat_truncate_time(inode, NULL, S_CTIME | S_MTIME);
	if (wait) {
		err = ddfs_sync_inode(inode);
		if (err) {
			dd_inode->i_start = i_start;
			dd_inode->i_logstart = i_logstart;
			return err;
		}
	} else {
		mark_inode_dirty(inode);
	}

	inode->i_blocks = 0;

	{
		// Index of cluster entry in table.
		const unsigned cluster_no = dd_inode->i_logstart;
		// How many cluster indices fit in one cluster, in table.
		const unsigned cluster_idx_per_cluster = sbi->cluster_size / 4u;
		// Cluster of table on which `cluster_no` lays.
		const unsigned table_cluster_no_containing_cluster_no =
			cluster_no / cluster_idx_per_cluster;
		// Index of block on the cluster, on which `cluster_no` lays.
		const unsigned block_no_containing_cluster_no =
			(cluster_no % cluster_idx_per_cluster) /
			sbi->blocks_per_cluster;
		// Index of block on device, on which `cluster_no` lays.
		// Calculated:
		//    1 cluster for boot sector * blocks_per_cluster
		//    + table_cluster_no_containing_cluster_no * blocks_per_cluster
		//    +  block_no_containing_cluster_no
		const unsigned device_block_no_containing_cluster_no =
			sbi->blocks_per_cluster +
			table_cluster_no_containing_cluster_no *
				sbi->blocks_per_cluster +
			block_no_containing_cluster_no;
		// Cluster index on the block
		const unsigned cluster_idx_on_block =
			cluster_no % (sb->s_blocksize / 4u);

		DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE *cluster_index_ptr;

		lock_table(sbi);

		// Read the block
		bh = sb_bread(sb, device_block_no_containing_cluster_no);
		if (!bh) {
			dd_error("unable to read inode block for free ");
			return -EIO;
		}

		cluster_index_ptr =
			(DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE *)(bh->b_data) +
			cluster_idx_on_block;

		// Finally, write cluster as unused:
		*cluster_index_ptr = DDFS_CLUSTER_UNUSED;

		brelse(bh);

		unlock_table(sbi);
	}

	return 0;
}

static int writeback_inode(struct inode *inode)
{
	int ret;

	/* if we used wait=1, sync_inode_metadata waits for the io for the
	* inode to finish.  So wait=0 is sent down to sync_inode_metadata
	* and filemap_fdatawrite is used for the data blocks
	*/
	ret = sync_inode_metadata(inode, 0);
	if (!ret)
		ret = filemap_fdatawrite(inode->i_mapping);
	return ret;
}

int ddfs_flush_inodes(struct super_block *sb, struct inode *i1,
		      struct inode *i2)
{
	int ret = 0;
	if (i1)
		ret = writeback_inode(i1);
	if (!ret && i2)
		ret = writeback_inode(i2);
	if (!ret) {
		struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;
		ret = filemap_flush(mapping);
	}
	return ret;
}

void ddfs_truncate_blocks(struct inode *inode, loff_t offset)
{
	ddfs_free(inode, 0);
	ddfs_flush_inodes(inode->i_sb, inode, NULL);
}

static void ddfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);

	ddfs_truncate_blocks(inode, 0);

	// if (!inode->i_nlink) {
	// 	inode->i_size = 0;
	// 	fat_truncate_blocks(inode, 0);
	// } else {
	// 	fat_free_eofblocks(inode);
	// }

	invalidate_inode_buffers(inode);
	clear_inode(inode);
	// fat_cache_inval_inode(inode);
	// fat_detach(inode);
}

static void ddfs_put_super(struct super_block *sb)
{
	// Todo: put table inode
}

// Todo: implement?
// static int ddfs_statfs(struct dentry *dentry, struct kstatfs *buf)
// {
// 	struct super_block *sb = dentry->d_sb;
// 	struct ddfs_sb_info *sbi = DDFS_SB(sb);
// 	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

// 	/* If the count of free cluster is still unknown, counts it here. */
// 	if (sbi->free_clusters == -1 || !sbi->free_clus_valid) {
// 		int err = fat_count_free_clusters(dentry->d_sb);
// 		if (err)
// 			return err;
// 	}

// 	buf->f_type = dentry->d_sb->s_magic;
// 	buf->f_bsize = sbi->cluster_size;
// 	buf->f_blocks = sbi->max_cluster - FAT_START_ENT;
// 	buf->f_bfree = sbi->free_clusters;
// 	buf->f_bavail = sbi->free_clusters;
// 	buf->f_fsid.val[0] = (u32)id;
// 	buf->f_fsid.val[1] = (u32)(id >> 32);
// 	buf->f_namelen =
// 		(sbi->options.isvfat ? FAT_LFN_LEN : 12) * NLS_MAX_CHARSET_SIZE;

// 	return 0;
// }

static int ddfs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	return 0;
}

// static int ddfs_show_options(struct seq_file *m, struct dentry *root);
static const struct super_operations ddfs_sops = {
	.alloc_inode = ddfs_alloc_inode,
	.free_inode = ddfs_free_inode,
	.write_inode = ddfs_write_inode,
	.evict_inode = ddfs_evict_inode,
	.put_super = ddfs_put_super,
	// .statfs = ddfs_statfs,
	.remount_fs = ddfs_remount,

	// .show_options = ddfs_show_options,
};

// Todo: implement?
// static int ddfs_show_options(struct seq_file *m, struct dentry *root)
// {
// 	struct msdos_sb_info *sbi = MSDOS_SB(root->d_sb);
// 	struct fat_mount_options *opts = &sbi->options;
// 	int isvfat = opts->isvfat;

// 	if (!uid_eq(opts->fs_uid, GLOBAL_ROOT_UID))
// 		seq_printf(m, ",uid=%u",
// 			   from_kuid_munged(&init_user_ns, opts->fs_uid));
// 	if (!gid_eq(opts->fs_gid, GLOBAL_ROOT_GID))
// 		seq_printf(m, ",gid=%u",
// 			   from_kgid_munged(&init_user_ns, opts->fs_gid));
// 	seq_printf(m, ",fmask=%04o", opts->fs_fmask);
// 	seq_printf(m, ",dmask=%04o", opts->fs_dmask);
// 	if (opts->allow_utime)
// 		seq_printf(m, ",allow_utime=%04o", opts->allow_utime);
// 	if (sbi->nls_disk)
// 		/* strip "cp" prefix from displayed option */
// 		seq_printf(m, ",codepage=%s", &sbi->nls_disk->charset[2]);
// 	if (isvfat) {
// 		if (sbi->nls_io)
// 			seq_printf(m, ",iocharset=%s", sbi->nls_io->charset);

// 		switch (opts->shortname) {
// 		case VFAT_SFN_DISPLAY_WIN95 | VFAT_SFN_CREATE_WIN95:
// 			seq_puts(m, ",shortname=win95");
// 			break;
// 		case VFAT_SFN_DISPLAY_WINNT | VFAT_SFN_CREATE_WINNT:
// 			seq_puts(m, ",shortname=winnt");
// 			break;
// 		case VFAT_SFN_DISPLAY_WINNT | VFAT_SFN_CREATE_WIN95:
// 			seq_puts(m, ",shortname=mixed");
// 			break;
// 		case VFAT_SFN_DISPLAY_LOWER | VFAT_SFN_CREATE_WIN95:
// 			seq_puts(m, ",shortname=lower");
// 			break;
// 		default:
// 			seq_puts(m, ",shortname=unknown");
// 			break;
// 		}
// 	}
// 	if (opts->name_check != 'n')
// 		seq_printf(m, ",check=%c", opts->name_check);
// 	if (opts->usefree)
// 		seq_puts(m, ",usefree");
// 	if (opts->quiet)
// 		seq_puts(m, ",quiet");
// 	if (opts->showexec)
// 		seq_puts(m, ",showexec");
// 	if (opts->sys_immutable)
// 		seq_puts(m, ",sys_immutable");
// 	if (!isvfat) {
// 		if (opts->dotsOK)
// 			seq_puts(m, ",dotsOK=yes");
// 		if (opts->nocase)
// 			seq_puts(m, ",nocase");
// 	} else {
// 		if (opts->utf8)
// 			seq_puts(m, ",utf8");
// 		if (opts->unicode_xlate)
// 			seq_puts(m, ",uni_xlate");
// 		if (!opts->numtail)
// 			seq_puts(m, ",nonumtail");
// 		if (opts->rodir)
// 			seq_puts(m, ",rodir");
// 	}
// 	if (opts->flush)
// 		seq_puts(m, ",flush");
// 	if (opts->tz_set) {
// 		if (opts->time_offset)
// 			seq_printf(m, ",time_offset=%d", opts->time_offset);
// 		else
// 			seq_puts(m, ",tz=UTC");
// 	}
// 	if (opts->errors == FAT_ERRORS_CONT)
// 		seq_puts(m, ",errors=continue");
// 	else if (opts->errors == FAT_ERRORS_PANIC)
// 		seq_puts(m, ",errors=panic");
// 	else
// 		seq_puts(m, ",errors=remount-ro");
// 	if (opts->nfs == FAT_NFS_NOSTALE_RO)
// 		seq_puts(m, ",nfs=nostale_ro");
// 	else if (opts->nfs)
// 		seq_puts(m, ",nfs=stale_rw");
// 	if (opts->discard)
// 		seq_puts(m, ",discard");
// 	if (opts->dos1xfloppy)
// 		seq_puts(m, ",dos1xfloppy");

// 	return 0;
// }

// static struct dentry *ddfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
// 					int fh_len, int fh_type)
// {
// 	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
// 				    fat_nfs_get_inode);
// }

// static struct dentry *ddfs_fh_to_parent(struct super_block *sb, struct fid *fid,
// 					int fh_len, int fh_type)
// {
// 	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
// 				    fat_nfs_get_inode);
// }

// static inline int fat_get_dotdot_entry(struct inode *dir,
// 				       struct ddfs_dir_entry **de)
// {
// 	*de = NULL;
// 	return ddfs_find(dir, "..", *de);
// }

// static struct dentry *ddfs_get_parent(struct dentry *child_dir)
// {
// 	struct super_block *sb = child_dir->d_sb;
// 	struct ddfs_dir_entry *de;
// 	struct inode *parent_inode = NULL;
// 	struct ddfs_sb_info *sbi = DDFS_SB(sb);

// 	if (!fat_get_dotdot_entry(d_inode(child_dir), &bh, &de)) {
// 		int parent_logstart = fat_get_start(sbi, de);
// 		parent_inode = fat_dget(sb, parent_logstart);
// 		if (!parent_inode && sbi->options.nfs == FAT_NFS_NOSTALE_RO) {
// 			parent_inode = fat_rebuild_parent(sb, parent_logstart);
// 		}
// 	}

// 	return d_obtain_alias(parent_inode);
// }

const struct export_operations ddfs_export_ops = {
	// .fh_to_dentry = ddfs_fh_to_dentry,
	// .fh_to_parent = ddfs_fh_to_parent,
	// .get_parent = ddfs_get_parent,
};

static struct ddfs_dir_entry
ddfs_make_dir_entry(const struct dir_entry_ptrs *parts_ptrs)
{
	struct ddfs_dir_entry result;
	if (parts_ptrs->name.bh) {
		memcpy(result.name, parts_ptrs->name.ptr, 4);
	}
	if (parts_ptrs->size.bh) {
		result.size = *parts_ptrs->size.ptr;
	}
	if (parts_ptrs->attributes.bh) {
		result.attributes = *parts_ptrs->attributes.ptr;
	}
	if (parts_ptrs->first_cluster.bh) {
		result.first_cluster = *parts_ptrs->first_cluster.ptr;
	}

	return result;
}

static long ddfs_add_dir_entry(struct inode *dir, const struct qstr *qname,
			       struct ddfs_dir_entry *de)
{
	struct ddfs_inode_info *dd_idir = DDFS_I(dir);
	// Todo: handle no space on cluster

	const unsigned new_entry_index = dd_idir->number_of_entries;

	const struct dir_entry_ptrs parts_ptrs = access_dir_entries(
		dir, new_entry_index, DDFS_PART_NAME | DDFS_PART_FIRST_CLUSTER);
	int i;

	dd_print("ddfs_add_dir_entry, dir: %p, name: %s, de: %p", dir,
		 (const char *)qname->name, de);
	dump_dir_entry_ptrs(&parts_ptrs);

	++dd_idir->number_of_entries;

	// Set name
	if (!parts_ptrs.name.bh) {
		dd_error("unable to read inode block for name");
		goto fail_io;
	}

	dd_print("assigning name");
	for (i = 0; i < DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE; ++i) {
		parts_ptrs.name.ptr[i] = qname->name[i];
		if (!qname->name[i]) {
			break;
		}
	}

	dd_print("calling mark_buffer_dirty_inode");
	mark_buffer_dirty_inode(parts_ptrs.name.bh, dir);

	// Set first cluster
	if (!parts_ptrs.first_cluster.bh) {
		dd_error("unable to read inode block for first_cluster");
		goto fail_io;
	}

	*parts_ptrs.first_cluster.ptr = DDFS_CLUSTER_UNUSED;
	mark_buffer_dirty_inode(parts_ptrs.first_cluster.bh, dir);

	*de = ddfs_make_dir_entry(&parts_ptrs);

	release_dir_entries(&parts_ptrs,
			    DDFS_PART_NAME | DDFS_PART_FIRST_CLUSTER);

	dd_print("~ddfs_add_dir_entry 0");
	return 0;

fail_io:
	--dd_idir->number_of_entries;
	release_dir_entries(&parts_ptrs,
			    DDFS_PART_NAME | DDFS_PART_FIRST_CLUSTER);

	dd_print("~ddfs_add_dir_entry error: %d", -EIO);
	return -EIO;
}

const struct inode_operations ddfs_file_inode_operations = {
	// Todo: fill
	// .setattr = fat_setattr,
	// .getattr = fat_getattr,
	// .update_time = fat_update_time,
};

const struct file_operations ddfs_file_operations = {
	// Todo: fill
	// 	.llseek = generic_file_llseek,
	// 	.read_iter = generic_file_read_iter,
	// 	.write_iter = generic_file_write_iter,
	// 	.mmap = generic_file_mmap,
	// 	.release = fat_file_release,
	// 	.unlocked_ioctl = fat_generic_ioctl,
	// #ifdef CONFIG_COMPAT
	// 	.compat_ioctl = fat_generic_compat_ioctl,
	// #endif
	// 	.fsync = fat_file_fsync,
	// 	.splice_read = generic_file_splice_read,
	// 	.splice_write = iter_file_splice_write,
	// 	.fallocate = fat_fallocate,
};

static const struct address_space_operations ddfs_aops = {
	// Todo: fill
	// .readpage = fat_readpage,
	// .readpages = fat_readpages,
	// .writepage = fat_writepage,
	// .writepages = fat_writepages,
	// .write_begin = fat_write_begin,
	// .write_end = fat_write_end,
	// .direct_IO = fat_direct_IO,
	// .bmap = _fat_bmap
};

/* doesn't deal with root inode */
int ddfs_fill_inode(struct inode *inode, struct ddfs_dir_entry *de)
{
	struct ddfs_inode_info *dd_inode = DDFS_I(inode);

	dd_print("ddfs_fill_inode: inode: %p, de: %p", inode, de);
	dump_ddfs_inode_info(dd_inode);
	dump_ddfs_dir_entry(de);

	dd_inode->i_pos = 0;
	// inode->i_uid = sbi->options.fs_uid;
	// inode->i_gid = sbi->options.fs_gid;
	inode_inc_iversion(inode);
	inode->i_generation = get_seconds();

	// Todo: Handle directory filling

	dd_inode->i_start = de->first_cluster;

	dd_inode->i_logstart = dd_inode->i_start;
	inode->i_size = le32_to_cpu(de->size);
	inode->i_op = &ddfs_file_inode_operations;
	inode->i_fop = &ddfs_file_operations;
	inode->i_mapping->a_ops = &ddfs_aops;
	dd_inode->mmu_private = inode->i_size;

	inode->i_blocks = inode->i_size / inode->i_sb->s_blocksize;

	dd_print("filled inode");
	dump_ddfs_inode_info(dd_inode);

	dd_print("~ddfs_fill_inode 0");
	return 0;
}

struct inode *ddfs_build_inode(struct super_block *sb,
			       struct ddfs_dir_entry *de)
{
	struct inode *inode;
	int err;

	lock_inode_build(DDFS_SB(sb));

	dd_print("ddfs_build_inode, de: ");
	dump_ddfs_dir_entry(de);

	dd_print("calling new_inode");
	inode = new_inode(sb);
	if (!inode) {
		dd_print("new_inode call failed");
		inode = ERR_PTR(-ENOMEM);
		goto out;
	}
	dd_print("new_inode call succeed");

	inode->i_ino = iunique(sb, 128); // todo: 128 is probably not needed
	inode_set_iversion(inode, 1);

	dd_print("calling ddfs_fill_inode");
	err = ddfs_fill_inode(inode, de);
	if (err) {
		dd_print("ddfs_fill_inode call failed");
		iput(inode);
		inode = ERR_PTR(err);
		goto out;
	}

	dd_print("ddfs_fill_inode call succeed");

	// fat_attach(inode, i_pos);
	insert_inode_hash(inode);

out:
	unlock_inode_build(DDFS_SB(sb));
	dd_print("~ddfs_fill_inode, inode: %p", inode);
	return inode;
}

static int ddfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct ddfs_sb_info *sbi = DDFS_SB(sb);
	struct inode *inode;
	int err;
	struct ddfs_dir_entry de;

	dd_print("ddfs_create, inode: %p, dentry: %p, mode: %u, excl: %d", dir,
		 dentry, mode, (int)excl);
	dump_ddfs_inode_info(DDFS_I(dir));

	lock_data(sbi);

	// ts = current_time(dir);
	// err = vfat_add_entry(dir, &dentry->d_name, 0, 0, &ts, &slot_info);
	dd_print("calling ddfs_add_dir_entry");
	err = ddfs_add_dir_entry(dir, &dentry->d_name, &de);
	if (err) {
		dd_print("ddfs_add_dir_entry failed with err: %d", err);
		goto out;
	}
	dd_print("ddfs_add_dir_entry succeed");

	inode_inc_iversion(dir);

	dd_print("calling ddfs_build_inode");
	inode = ddfs_build_inode(sb, &de);
	if (IS_ERR(inode)) {
		dd_print("ddfs_build_inode call failed");
		err = PTR_ERR(inode);
		goto out;
	}
	dd_print("ddfs_build_inode call succeed");

	inode_inc_iversion(inode);
	// fat_truncate_time(inode, &ts, S_ATIME | S_CTIME | S_MTIME);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	dd_print("calling d_instantiate");
	d_instantiate(dentry, inode);

out:
	unlock_data(sbi);
	dd_print("~ddfs_create %d", err);
	return err;
}

static int ddfs_find(struct inode *dir, const char *name,
		     struct ddfs_dir_entry *dest_de)
{
	int entry_index;
	struct ddfs_inode_info *dd_dir = DDFS_I(dir);
	// char name_buf[] = { name[0], name[1], name[2], name[3], '\0' };

	dd_print("ddfs_find, dir: %p, name: %s, dest_de: %p", dir, name,
		 dest_de);

	dump_ddfs_inode_info(dd_dir);
	// const unsigned int len = vfat_striptail_len(qname);
	// if (len == 0 || len > 4) {
	// 	return -ENOENT;
	// }

	for (entry_index = 0; entry_index < dd_dir->number_of_entries;
	     ++entry_index) {
		int i;
		const struct dir_entry_ptrs entry_ptrs =
			access_dir_entries(dir, entry_index, DDFS_PART_NAME);

		dd_print("entry_index: %d", entry_index);
		dump_dir_entry_ptrs(&entry_ptrs);

		for (i = 0; i < 4; ++i) {
			if (entry_ptrs.name.ptr[i] == name[i] &&
			    entry_ptrs.name.ptr[i] == '\0') {
				dd_print("found entry at: %d", entry_index);

				memcpy(dest_de->name, entry_ptrs.name.ptr, i);
				dest_de->entry_index = entry_index;
				dest_de->size = *entry_ptrs.size.ptr;
				dest_de->first_cluster =
					*entry_ptrs.first_cluster.ptr;
				dest_de->attributes =
					*entry_ptrs.attributes.ptr;

				release_dir_entries(&entry_ptrs,
						    DDFS_PART_NAME);

				dd_print("~ddfs_find 0");
				return 0;
			}

			if (!entry_ptrs.name.ptr[i] || !name[i]) {
				break;
			}
		}

		release_dir_entries(&entry_ptrs, DDFS_PART_NAME);
	}

	dd_print("~ddfs_find %d", -ENOENT);
	return -ENOENT;
}

static struct dentry *ddfs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct ddfs_sb_info *sbi = DDFS_SB(sb);
	struct ddfs_dir_entry de;
	struct inode *inode;
	struct dentry *alias;
	int err;
	// char dname_buf[128] = { 0 };

	lock_data(sbi);

	dd_print("ddfs_lookup: dir: %p, dentry: %p, flags: %u", dir, dentry,
		 flags);
	dump_ddfs_inode_info(DDFS_I(dir));

	// dentry->d_op->d_dname(dentry, dname_buf, 128);

	err = ddfs_find(dir, (const char *)(dentry->d_name.name), &de);
	// err = ddfs_find(dir, dname_buf, &de);
	if (err) {
		if (err == -ENOENT) {
			inode = NULL;
			goto out;
		}
		goto error;
	}

	inode = ddfs_build_inode(sb, &de);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto error;
	}

	alias = d_find_alias(inode);
	/*
	 * Checking "alias->d_parent == dentry->d_parent" to make sure
	 * FS is not corrupted (especially double linked dir).
	 */
	if (alias && alias->d_parent == dentry->d_parent) {
		/*
		 * This inode has non anonymous-DCACHE_DISCONNECTED
		 * dentry. This means, the user did ->lookup() by an
		 * another name (longname vs 8.3 alias of it) in past.
		 *
		 * Switch to new one for reason of locality if possible.
		 */
		if (!S_ISDIR(inode->i_mode)) {
			d_move(alias, dentry);
		}
		iput(inode);
		unlock_data(sbi);
		return alias;
	} else {
		dput(alias);
	}

out:
	unlock_data(sbi);
	dd_print("~ddfs_lookup, inode: %p", inode);
	return d_splice_alias(inode, dentry);
error:
	unlock_data(sbi);
	dd_print("~ddfs_lookup error: %p", ERR_PTR(err));
	return ERR_PTR(err);
}

static int ddfs_unlink(struct inode *dir, struct dentry *dentry)
{
	dd_print("ddfs_unlink: dir: %p, dentry: %p", dir, dentry);
	dump_ddfs_inode_info(DDFS_I(dir));

	dd_print("~ddfs_unlink %d", -EINVAL);
	return -EINVAL;
	////

	// 	struct inode *inode = d_inode(dentry);
	// 	struct super_block *sb = dir->i_sb;
	// 	struct fat_slot_info sinfo;
	// 	int err;

	// 	mutex_lock(&MSDOS_SB(sb)->s_lock);

	// 	err = vfat_find(dir, &dentry->d_name, &sinfo);
	// 	if (err)
	// 		goto out;

	// 	err = fat_remove_entries(dir, &sinfo); /* and releases bh */
	// 	if (err)
	// 		goto out;
	// 	clear_nlink(inode);
	// 	fat_truncate_time(inode, NULL, S_ATIME | S_MTIME);
	// 	fat_detach(inode);
	// 	vfat_d_version_set(dentry, inode_query_iversion(dir));
	// out:
	// 	mutex_unlock(&MSDOS_SB(sb)->s_lock);

	// 	return err;
}

static int ddfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	dd_print("ddfs_mkdir: dir: %p, dentry: %p, mode: %u", dir, dentry,
		 mode);
	dump_ddfs_inode_info(DDFS_I(dir));

	dd_print("~ddfs_mkdir %d", -EINVAL);
	return -EINVAL;

	// 	struct super_block *sb = dir->i_sb;
	// 	struct inode *inode;
	// 	struct fat_slot_info sinfo;
	// 	struct timespec64 ts;
	// 	int err, cluster;

	// 	mutex_lock(&MSDOS_SB(sb)->s_lock);

	// 	ts = current_time(dir);
	// 	cluster = fat_alloc_new_dir(dir, &ts);
	// 	if (cluster < 0) {
	// 		err = cluster;
	// 		goto out;
	// 	}
	// 	err = vfat_add_entry(dir, &dentry->d_name, 1, cluster, &ts, &sinfo);
	// 	if (err)
	// 		goto out_free;
	// 	inode_inc_iversion(dir);
	// 	inc_nlink(dir);

	// 	inode = fat_build_inode(sb, sinfo.de, sinfo.i_pos);
	// 	brelse(sinfo.bh);
	// 	if (IS_ERR(inode)) {
	// 		err = PTR_ERR(inode);
	// 		/* the directory was completed, just return a error */
	// 		goto out;
	// 	}
	// 	inode_inc_iversion(inode);
	// 	set_nlink(inode, 2);
	// 	fat_truncate_time(inode, &ts, S_ATIME | S_CTIME | S_MTIME);
	// 	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	// 	d_instantiate(dentry, inode);

	// 	mutex_unlock(&MSDOS_SB(sb)->s_lock);
	// 	return 0;

	// out_free:
	// 	fat_free_clusters(dir, cluster);
	// out:
	// 	mutex_unlock(&MSDOS_SB(sb)->s_lock);
	// 	return err;
}

static int ddfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	dd_print("ddfs_rmdir: dir: %p, dentry: %p", dir, dentry);
	dump_ddfs_inode_info(DDFS_I(dir));

	dd_print("~ddfs_rmdir %d", -EINVAL);
	return -EINVAL;

	// 	struct inode *inode = d_inode(dentry);
	// 	struct super_block *sb = dir->i_sb;
	// 	struct fat_slot_info sinfo;
	// 	int err;

	// 	mutex_lock(&MSDOS_SB(sb)->s_lock);

	// 	err = fat_dir_empty(inode);
	// 	if (err)
	// 		goto out;
	// 	err = vfat_find(dir, &dentry->d_name, &sinfo);
	// 	if (err)
	// 		goto out;

	// 	err = fat_remove_entries(dir, &sinfo); /* and releases bh */
	// 	if (err)
	// 		goto out;
	// 	drop_nlink(dir);

	// 	clear_nlink(inode);
	// 	fat_truncate_time(inode, NULL, S_ATIME | S_MTIME);
	// 	fat_detach(inode);
	// 	vfat_d_version_set(dentry, inode_query_iversion(dir));
	// out:
	// 	mutex_unlock(&MSDOS_SB(sb)->s_lock);

	// 	return err;
}

static int ddfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags)
{
	dd_print(
		"ddfs_rename: old_dir: %p, old_dentry: %p, new_dir: %p, new_dentry: %p, flags: %u",
		old_dir, old_dentry, new_dir, new_dentry, flags);
	dd_print("old_dir");
	dump_ddfs_inode_info(DDFS_I(old_dir));
	dd_print("new_dir");
	dump_ddfs_inode_info(DDFS_I(new_dir));

	dd_print("~ddfs_rename %d", -EINVAL);
	return -EINVAL;
	return -EINVAL;

	// 	struct buffer_head *dotdot_bh;
	// 	struct msdos_dir_entry *dotdot_de;
	// 	struct inode *old_inode, *new_inode;
	// 	struct fat_slot_info old_sinfo, sinfo;
	// 	struct timespec64 ts;
	// 	loff_t new_i_pos;
	// 	int err, is_dir, update_dotdot, corrupt = 0;
	// 	struct super_block *sb = old_dir->i_sb;

	// 	if (flags & ~RENAME_NOREPLACE)
	// 		return -EINVAL;

	// 	old_sinfo.bh = sinfo.bh = dotdot_bh = NULL;
	// 	old_inode = d_inode(old_dentry);
	// 	new_inode = d_inode(new_dentry);
	// 	mutex_lock(&MSDOS_SB(sb)->s_lock);
	// 	err = vfat_find(old_dir, &old_dentry->d_name, &old_sinfo);
	// 	if (err)
	// 		goto out;

	// 	is_dir = S_ISDIR(old_inode->i_mode);
	// 	update_dotdot = (is_dir && old_dir != new_dir);
	// 	if (update_dotdot) {
	// 		if (fat_get_dotdot_entry(old_inode, &dotdot_bh, &dotdot_de)) {
	// 			err = -EIO;
	// 			goto out;
	// 		}
	// 	}

	// 	ts = current_time(old_dir);
	// 	if (new_inode) {
	// 		if (is_dir) {
	// 			err = fat_dir_empty(new_inode);
	// 			if (err)
	// 				goto out;
	// 		}
	// 		new_i_pos = MSDOS_I(new_inode)->i_pos;
	// 		fat_detach(new_inode);
	// 	} else {
	// 		err = vfat_add_entry(new_dir, &new_dentry->d_name, is_dir, 0,
	// 				     &ts, &sinfo);
	// 		if (err)
	// 			goto out;
	// 		new_i_pos = sinfo.i_pos;
	// 	}
	// 	inode_inc_iversion(new_dir);

	// 	fat_detach(old_inode);
	// 	fat_attach(old_inode, new_i_pos);
	// 	if (IS_DIRSYNC(new_dir)) {
	// 		err = fat_sync_inode(old_inode);
	// 		if (err)
	// 			goto error_inode;
	// 	} else
	// 		mark_inode_dirty(old_inode);

	// 	if (update_dotdot) {
	// 		fat_set_start(dotdot_de, MSDOS_I(new_dir)->i_logstart);
	// 		mark_buffer_dirty_inode(dotdot_bh, old_inode);
	// 		if (IS_DIRSYNC(new_dir)) {
	// 			err = sync_dirty_buffer(dotdot_bh);
	// 			if (err)
	// 				goto error_dotdot;
	// 		}
	// 		drop_nlink(old_dir);
	// 		if (!new_inode)
	// 			inc_nlink(new_dir);
	// 	}

	// 	err = fat_remove_entries(old_dir, &old_sinfo); /* and releases bh */
	// 	old_sinfo.bh = NULL;
	// 	if (err)
	// 		goto error_dotdot;
	// 	inode_inc_iversion(old_dir);
	// 	fat_truncate_time(old_dir, &ts, S_CTIME | S_MTIME);
	// 	if (IS_DIRSYNC(old_dir))
	// 		(void)fat_sync_inode(old_dir);
	// 	else
	// 		mark_inode_dirty(old_dir);

	// 	if (new_inode) {
	// 		drop_nlink(new_inode);
	// 		if (is_dir)
	// 			drop_nlink(new_inode);
	// 		fat_truncate_time(new_inode, &ts, S_CTIME);
	// 	}
	// out:
	// 	brelse(sinfo.bh);
	// 	brelse(dotdot_bh);
	// 	brelse(old_sinfo.bh);
	// 	mutex_unlock(&MSDOS_SB(sb)->s_lock);

	// 	return err;

	// error_dotdot:
	// 	/* data cluster is shared, serious corruption */
	// 	corrupt = 1;

	// 	if (update_dotdot) {
	// 		fat_set_start(dotdot_de, MSDOS_I(old_dir)->i_logstart);
	// 		mark_buffer_dirty_inode(dotdot_bh, old_inode);
	// 		corrupt |= sync_dirty_buffer(dotdot_bh);
	// 	}
	// error_inode:
	// 	fat_detach(old_inode);
	// 	fat_attach(old_inode, old_sinfo.i_pos);
	// 	if (new_inode) {
	// 		fat_attach(new_inode, new_i_pos);
	// 		if (corrupt)
	// 			corrupt |= fat_sync_inode(new_inode);
	// 	} else {
	// 		/*
	// 		 * If new entry was not sharing the data cluster, it
	// 		 * shouldn't be serious corruption.
	// 		 */
	// 		int err2 = fat_remove_entries(new_dir, &sinfo);
	// 		if (corrupt)
	// 			corrupt |= err2;
	// 		sinfo.bh = NULL;
	// 	}
	// 	if (corrupt < 0) {
	// 		fat_fs_error(new_dir->i_sb,
	// 			     "%s: Filesystem corrupted (i_pos %lld)", __func__,
	// 			     sinfo.i_pos);
	// 	}
	// 	goto out;
}

// Todo: Should implement?
// int ddfs_setattr(struct dentry *dentry, struct iattr *attr)
// {
// 	struct msdos_sb_info *sbi = MSDOS_SB(dentry->d_sb);
// 	struct inode *inode = d_inode(dentry);
// 	unsigned int ia_valid;
// 	int error;

// 	/* Check for setting the inode time. */
// 	ia_valid = attr->ia_valid;
// 	if (ia_valid & TIMES_SET_FLAGS) {
// 		if (fat_allow_set_time(sbi, inode))
// 			attr->ia_valid &= ~TIMES_SET_FLAGS;
// 	}

// 	error = setattr_prepare(dentry, attr);
// 	attr->ia_valid = ia_valid;
// 	if (error) {
// 		if (sbi->options.quiet)
// 			error = 0;
// 		goto out;
// 	}

// 	/*
// 	 * Expand the file. Since inode_setattr() updates ->i_size
// 	 * before calling the ->truncate(), but FAT needs to fill the
// 	 * hole before it. XXX: this is no longer true with new truncate
// 	 * sequence.
// 	 */
// 	if (attr->ia_valid & ATTR_SIZE) {
// 		inode_dio_wait(inode);

// 		if (attr->ia_size > inode->i_size) {
// 			error = fat_cont_expand(inode, attr->ia_size);
// 			if (error || attr->ia_valid == ATTR_SIZE)
// 				goto out;
// 			attr->ia_valid &= ~ATTR_SIZE;
// 		}
// 	}

// 	if (((attr->ia_valid & ATTR_UID) &&
// 	     (!uid_eq(attr->ia_uid, sbi->options.fs_uid))) ||
// 	    ((attr->ia_valid & ATTR_GID) &&
// 	     (!gid_eq(attr->ia_gid, sbi->options.fs_gid))) ||
// 	    ((attr->ia_valid & ATTR_MODE) && (attr->ia_mode & ~FAT_VALID_MODE)))
// 		error = -EPERM;

// 	if (error) {
// 		if (sbi->options.quiet)
// 			error = 0;
// 		goto out;
// 	}

// 	/*
// 	 * We don't return -EPERM here. Yes, strange, but this is too
// 	 * old behavior.
// 	 */
// 	if (attr->ia_valid & ATTR_MODE) {
// 		if (fat_sanitize_mode(sbi, inode, &attr->ia_mode) < 0)
// 			attr->ia_valid &= ~ATTR_MODE;
// 	}

// 	if (attr->ia_valid & ATTR_SIZE) {
// 		error = fat_block_truncate_page(inode, attr->ia_size);
// 		if (error)
// 			goto out;
// 		down_write(&MSDOS_I(inode)->truncate_lock);
// 		truncate_setsize(inode, attr->ia_size);
// 		fat_truncate_blocks(inode, attr->ia_size);
// 		up_write(&MSDOS_I(inode)->truncate_lock);
// 	}

// 	/*
// 	 * setattr_copy can't truncate these appropriately, so we'll
// 	 * copy them ourselves
// 	 */
// 	if (attr->ia_valid & ATTR_ATIME)
// 		fat_truncate_time(inode, &attr->ia_atime, S_ATIME);
// 	if (attr->ia_valid & ATTR_CTIME)
// 		fat_truncate_time(inode, &attr->ia_ctime, S_CTIME);
// 	if (attr->ia_valid & ATTR_MTIME)
// 		fat_truncate_time(inode, &attr->ia_mtime, S_MTIME);
// 	attr->ia_valid &= ~(ATTR_ATIME | ATTR_CTIME | ATTR_MTIME);

// 	setattr_copy(inode, attr);
// 	mark_inode_dirty(inode);
// out:
// 	return error;
// }
// EXPORT_SYMBOL_GPL(ddfs_setattr);

// Todo: Should implement?
// int ddfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
// 		 unsigned int flags)
// {
// 	struct inode *inode = d_inode(path->dentry);
// 	generic_fillattr(inode, stat);
// 	stat->blksize = MSDOS_SB(inode->i_sb)->cluster_size;

// 	if (MSDOS_SB(inode->i_sb)->options.nfs == FAT_NFS_NOSTALE_RO) {
// 		/* Use i_pos for ino. This is used as fileid of nfs. */
// 		stat->ino = fat_i_pos_read(MSDOS_SB(inode->i_sb), inode);
// 	}
// 	return 0;
// }
// EXPORT_SYMBOL_GPL(ddfs_getattr);

// Todo: should implement?
// int ddfs_update_time(struct inode *inode, struct timespec64 *now, int flags)
// {
// 	int iflags = I_DIRTY_TIME;
// 	bool dirty = false;

// 	if (inode->i_ino == MSDOS_ROOT_INO)
// 		return 0;

// 	fat_truncate_time(inode, now, flags);
// 	if (flags & S_VERSION)
// 		dirty = inode_maybe_inc_iversion(inode, false);
// 	if ((flags & (S_ATIME | S_CTIME | S_MTIME)) &&
// 	    !(inode->i_sb->s_flags & SB_LAZYTIME))
// 		dirty = true;

// 	if (dirty)
// 		iflags |= I_DIRTY_SYNC;
// 	__mark_inode_dirty(inode, iflags);
// 	return 0;
// }
// EXPORT_SYMBOL_GPL(ddfs_update_time);

static const struct inode_operations ddfs_dir_inode_operations = {
	.create = ddfs_create,
	.lookup = ddfs_lookup,
	.unlink = ddfs_unlink,
	.mkdir = ddfs_mkdir,
	.rmdir = ddfs_rmdir,
	.rename = ddfs_rename,
	// .setattr = ddfs_setattr,
	// .getattr = ddfs_getattr,
	// .update_time = ddfs_update_time,
};

const struct file_operations ddfs_dir_operations = {
	.llseek = generic_file_llseek,
	.read = generic_read_dir,
	// .iterate_shared = fat_readdir,
	// #ifdef CONFIG_COMPAT
	// .compat_ioctl	= fat_compat_dir_ioctl,
	// #endif
	// .fsync		= fat_file_fsync,
};

static int ddfs_revalidate(struct dentry *dentry, unsigned int flags)
{
	dd_print("ddfs_revalidate: dentry: %p, flags: %u", dentry, flags);
	// if (flags & LOOKUP_RCU)
	// 	return -ECHILD;

	// /* This is not negative dentry. Always valid. */
	// if (d_really_is_positive(dentry))
	// 	return 1;
	// return vfat_revalidate_shortname(dentry);

	// Todo: probably should be handled
	dd_print("~ddfs_revalidate 0");
	return 0;
}

static int ddfs_hash(const struct dentry *dentry, struct qstr *qstr)
{
	// qstr->hash = full_name_hash(dentry, qstr->name, vfat_striptail_len(qstr));
	qstr->hash = full_name_hash(dentry, qstr->name,
				    DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE);
	return 0;
}

static int ddfs_cmp(const struct dentry *dentry, unsigned int len,
		    const char *str, const struct qstr *name)
{
	return !(strncmp(name->name, str, DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE) ==
		 0);
}

static const struct dentry_operations ddfs_dentry_ops = {
	.d_revalidate = ddfs_revalidate,
	.d_hash = ddfs_hash,
	.d_compare = ddfs_cmp,
};

struct ddfs_boot_sector {
	__u32 sector_size;
	__u32 sectors_per_cluster;
	__u32 number_of_clusters;
};

long ddfs_read_boot_sector(struct super_block *sb, void *data,
			   struct ddfs_boot_sector *boot_sector)
{
	dd_print("ddfs_read_boot_sector");
	memcpy(boot_sector, data, sizeof(struct ddfs_boot_sector));
	dd_print("~ddfs_read_boot_sector 0");
	return 0;
}

void log_boot_sector(struct ddfs_boot_sector *boot_sector)
{
	dd_print("sector_size: %u, s/c: %u, number_of_clusters: %u",
		 (unsigned)boot_sector->sector_size,
		 (unsigned)boot_sector->sectors_per_cluster,
		 (unsigned)boot_sector->number_of_clusters);
}

unsigned int calculate_data_offset(struct ddfs_sb_info *sbi)
{
	unsigned int first_data_cluster = 1; // 1 for boot sector
	unsigned int table_end = sbi->table_offset + sbi->table_size;

	first_data_cluster += table_end / sbi->cluster_size;

	if (table_end % sbi->cluster_size != 0) {
		++first_data_cluster;
	}

	return first_data_cluster * sbi->cluster_size;
}

/* Convert attribute bits and a mask to the UNIX mode. */
static inline umode_t ddfs_make_mode(struct ddfs_sb_info *sbi, u8 attrs,
				     umode_t mode)
{
	if (attrs & DDFS_DIR_ATTR) {
		// return (mode & ~sbi->options.fs_dmask) | S_IFDIR;
		return DDFS_DEFAULT_MODE | S_IFDIR;
	}

	return 0;
}

static int ddfs_read_root(struct inode *inode)
{
	struct ddfs_sb_info *sbi = DDFS_SB(inode->i_sb);
	struct ddfs_inode_info *dd_inode = DDFS_I(inode);

	dd_print("ddfs_read_root %p", inode);

	dd_inode->i_pos = DDFS_ROOT_INO;
	// inode->i_uid = sbi->options.fs_uid;
	// inode->i_gid = sbi->options.fs_gid;
	inode_inc_iversion(inode);

	inode->i_generation = 0;
	inode->i_mode = ddfs_make_mode(sbi, DDFS_DIR_ATTR, S_IRWXUGO);
	inode->i_op = sbi->dir_ops;
	inode->i_fop = &ddfs_dir_operations;

	dd_inode->i_start = sbi->root_cluster;

	// Todo: handle root bigget than one cluster
	inode->i_size = sbi->cluster_size;
	inode->i_blocks = sbi->blocks_per_cluster;

	dd_inode->i_logstart = 0;
	dd_inode->mmu_private = inode->i_size;

	dd_inode->i_attrs |= DDFS_DIR_ATTR;

	dd_print("set up root:");
	dump_ddfs_inode_info(dd_inode);

	// inode->i_mtime.tv_sec = inode->i_atime.tv_sec = inode->i_ctime.tv_sec =0;
	// inode->i_mtime.tv_nsec = inode->i_atime.tv_nsec =inode->i_ctime.tv_nsec = 0;
	// set_nlink(inode, fat_subdirs(inode) + 2);

	dd_print("~ddfs_read_root 0");

	return 0;
}

static int ddfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct ddfs_sb_info *sbi;
	long error;
	struct buffer_head *bh;
	struct ddfs_boot_sector boot_sector;
	struct inode *root_inode;

	dd_print("ddfs_fill_super");

	sbi = kzalloc(sizeof(struct ddfs_sb_info), GFP_KERNEL);
	if (!sbi) {
		dd_error("kzalloc of sbi failed");
		dd_print("~ddfs_fill_super %d", -ENOMEM);
		return -ENOMEM;
	}
	sb->s_fs_info = sbi;

	sb->s_flags |= SB_NODIRATIME;
	sb->s_magic = DDFS_SUPER_MAGIC;
	sb->s_op = &ddfs_sops;
	sb->s_export_op = &ddfs_export_ops;
	sb->s_time_gran = 1;
	// mutex_init(&sbi->nfs_build_inode_lock);
	// ratelimit_state_init(&sbi->ratelimit, DEFAULT_RATELIMIT_INTERVAL,
	// 		     DEFAULT_RATELIMIT_BURST);

	// error = parse_options(sb, data, isvfat, silent, &debug, &sbi->options);
	// if (error) {
	// goto out_fail;
	// }

	// sb->s_fs_info->dir_ops = &ddfs_dir_inode_operations;
	sb->s_d_op = &ddfs_dentry_ops;

	error = -EIO;
	sb_min_blocksize(sb, 512);
	bh = sb_bread(sb, 0);
	if (bh == NULL) {
		dd_error("unable to read SB");
		goto out_fail;
	}

	error = ddfs_read_boot_sector(sb, bh->b_data, &boot_sector);
	if (error == -EINVAL) {
		dd_error("unable to read boot sector");
		goto out_fail;
	}
	brelse(bh);
	log_boot_sector(&boot_sector);

	sbi->blocks_per_cluster = boot_sector.sectors_per_cluster;

	mutex_init(&sbi->s_lock);
	sbi->dir_ops = &ddfs_dir_inode_operations;
	sbi->cluster_size = sb->s_blocksize * sbi->blocks_per_cluster;
	sbi->number_of_table_entries = boot_sector.number_of_clusters;
	sbi->table_offset = sbi->cluster_size;
	sbi->table_size =
		boot_sector.number_of_clusters * sizeof(struct ddfs_dir_entry);
	sbi->data_offset = calculate_data_offset(sbi);
	sbi->data_cluster_no = sbi->data_offset / sbi->cluster_size;
	sbi->root_cluster = sbi->data_cluster_no;
	sbi->block_size = sb->s_blocksize;

	sbi->entries_per_cluster =
		sbi->cluster_size / sizeof(DDFS_DIR_ENTRY_SIZE_TYPE);

	sbi->name_entries_offset = 0;
	sbi->attributes_entries_offset =
		sbi->entries_per_cluster * DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE;
	sbi->size_entries_offset =
		sbi->attributes_entries_offset +
		sbi->entries_per_cluster *
			sizeof(DDFS_DIR_ENTRY_ATTRIBUTES_TYPE);
	sbi->first_cluster_entries_offset =
		sbi->size_entries_offset +
		sbi->entries_per_cluster * sizeof(DDFS_DIR_ENTRY_SIZE_TYPE);

	// Make root inode
	dd_print("Making root inode");
	root_inode = new_inode(sb);
	if (!root_inode) {
		dd_print("new_inode for root node failed");
		goto out_fail;
	}
	dd_print("root_inode ptr: %p", root_inode);

	root_inode->i_ino = 1;
	dd_print("calling inode_set_iversion(root_inode, 1)");
	inode_set_iversion(root_inode, 1);

	dd_print("calling ddfs_read_root");
	error = ddfs_read_root(root_inode);
	if (error) {
		iput(root_inode);
		dd_print("ddfs_read_root failed with: %ld", error);
		goto out_fail;
	}
	dd_print("ddfs_read_root succeed");

	dd_print("calling insert_inode_hash");
	insert_inode_hash(root_inode);
	dd_print("insert_inode_hash call succeed");

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		dd_print("d_make_root root inode failed");
		goto out_fail;
	}

	dd_print("making root_inode success. root_inode: %p, sb->s_root: %p",
		 root_inode, sb->s_root);

	dd_print("~ddfs_fill_super 0");

	return 0;

out_fail:
	sb->s_fs_info = NULL;
	kfree(sbi);
	dd_print("~ddfs_fill_super %ld", error);
	return error;
}

static struct dentry *ddfs_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name, void *data)
{
	struct dentry *result;
	dd_print("ddfs_mount");
	result = mount_bdev(fs_type, flags, dev_name, data, ddfs_fill_super);
	dd_print("~ddfs_mount: %p", result);
	return result;
}

static struct file_system_type ddfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "ddfs",
	.mount = ddfs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};

static void init_once(void *foo)
{
	struct ddfs_inode_info *ei = (struct ddfs_inode_info *)foo;

	spin_lock_init(&ei->cache_lru_lock);
	ei->nr_caches = 0;
	ei->cache_valid_id = 1;
	INIT_LIST_HEAD(&ei->cache_lru);
	INIT_HLIST_NODE(&ei->i_fat_hash);
	INIT_HLIST_NODE(&ei->i_dir_hash);
	inode_init_once(&ei->ddfs_inode);
}

static int __init ddfs_init_inodecache(void)
{
	dd_print("ddfs_init_inodecache");

	ddfs_inode_cachep = kmem_cache_create(
		"ddfs_inode_cachep", sizeof(struct ddfs_inode_info), 0,
		(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_ACCOUNT),
		init_once);

	if (ddfs_inode_cachep == NULL) {
		dd_print("kmem_cache_create failed");
		dd_print("~ddfs_init_inodecache %d", -ENOMEM);
		return -ENOMEM;
	}
	dd_print("kmem_cache_create succeed");

	dd_print("~ddfs_init_inodecache 0");
	return 0;
}

static void __exit ddfs_destroy_inodecache(void)
{
	dd_print("ddfs_destroy_inodecache");
	rcu_barrier();
	kmem_cache_destroy(ddfs_inode_cachep);
	dd_print("~ddfs_destroy_inodecache");
}

static int __init init_ddfs_fs(void)
{
	int err;
	dd_print("init_ddfs_fs");

	err = ddfs_init_inodecache();
	if (err) {
		dd_print("ddfs_init_inodecache failed with %d", err);
		dd_print("~init_ddfs_fs %d", err);
		return err;
	}

	err = register_filesystem(&ddfs_fs_type);
	dd_print("~init_ddfs_fs");
	return err;
}

static void __exit exit_ddfs_fs(void)
{
	dd_print("exit_ddfs_fs");

	dd_print("calling ddfs_destroy_inodecache");
	ddfs_destroy_inodecache();

	unregister_filesystem(&ddfs_fs_type);
	dd_print("~exit_ddfs_fs");
}

MODULE_ALIAS_FS("ddfs");

module_init(init_ddfs_fs);
module_exit(exit_ddfs_fs);

//////