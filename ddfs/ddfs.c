#include <linux/init.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/iversion.h>

#define DDFS_SUPER_MAGIC 0xddf5
#define DDFS_CLUSTER_UNUSED 0xfffffffe
#define DDFS_CLUSTER_EOF 0xffffffff

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
	struct inode ddfs_inode;
};

#define DDFS_DIR_ENTRY_NAME_TYPE __u8
#define DDFS_DIR_ENTRY_ATTRIBUTES_TYPE __u8
#define DDFS_DIR_ENTRY_SIZE_TYPE __u64
#define DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE __u32

struct ddfs_dir_entry {
#define DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE 4
	DDFS_DIR_ENTRY_NAME_TYPE name[DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE];
#define DDFS_FILE_ATTR 1
#define DDFS_DIR_ATTR 2
	DDFS_DIR_ENTRY_ATTRIBUTES_TYPE attributes;
	DDFS_DIR_ENTRY_SIZE_TYPE size;
	DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE first_cluster;
};

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

	unsigned long block_size; // Size of block (sector) in bytes

	unsigned int entries_per_cluster; // Dir entries per cluster

	unsigned int name_entries_offset;
	unsigned int attributes_entries_offset;
	unsigned int size_entries_offset;
	unsigned int first_cluster_entries_offset;

	struct mutex table_lock;
};

static inline struct ddfs_sb_info *DDFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static struct kmem_cache *ddfs_inode_cachep;

static struct inode *ddfs_alloc_inode(struct super_block *sb)
{
	struct msdos_inode_info *ei;
	ei = kmem_cache_alloc(ddfs_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	init_rwsem(&ei->truncate_lock);
	return &ei->ddfs_inode;
}

static void ddfs_free_inode(struct inode *inode)
{
	kmem_cache_free(ddfs_inode_cachep, MSDOS_I(inode));
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
	time64_to_tm(ts->tv_sec, -fat_tz_offset(sbi), &tm);

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
	struct ddfs_dir_entry *raw_entry;
	loff_t i_pos;
	sector_t blocknr;
	int err, offset;

retry:
	// i_pos = ddfs_i_pos_read(sbi, inode);
	i_pos = DDFS_I(inode)->i_pos;
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
	if (i_pos != DDFS_I(inode)->i_pos) {
		// spin_unlock(&sbi->inode_hash_lock);
		brelse(bh);
		goto retry;
	}

	// Todo check whether entry index is inside cluster

	// Write first_cluster
	const unsigned first_cluster_offset =
		sbi->first_cluster_entries_offset +
		DDFS_I(inode)->entry_index *
			sizeof(DDFS_DIR_ENTRY_FIRST_CLUSTER_TYPE);
	*((__u32 *)(bh->b_data + size_offset)) = DDFS_I(inode)->i_logstart;

	// Write size
	const unsigned size_offset =
		sbi->size_entries_offset +
		DDFS_I(inode)->entry_index * sizeof(DDFS_DIR_ENTRY_SIZE_TYPE);
	*((__u32 *)(bh->b_data + size_offset)) = inode->i_size;

	// Write dummy attributes
	const unsigned attributes_offset =
		sbi->attributes_entries_offset +
		DDFS_I(inode)->entry_index *
			sizeof(DDFS_DIR_ENTRY_ATTRIBUTES_TYPE);
	*((__u8 *)(bh->b_data + size_offset)) = DDFS_FILE_ATTR;

	/////////////////////////////////////////
	// raw_entry = &((struct ddfs_dir_entry *)(bh->b_data))[offset];
	// if (S_ISDIR(inode->i_mode)) {
	// 	raw_entry->size = 0;
	// } else {
	// 	raw_entry->size = cpu_to_le32(inode->i_size);
	// }

	// raw_entry->attr = ddfs_make_attrs(inode);
	// ddfs_set_start(raw_entry, DDFS_I(inode)->i_logstart);
	// ddfs_time_unix2fat(sbi, &inode->i_mtime, &raw_entry->time,
	// 		   &raw_entry->date, NULL);

	// spin_unlock(&sbi->inode_hash_lock);
	mark_buffer_dirty(bh);
	err = 0;
	if (wait)
		err = sync_dirty_buffer(bh);
	brelse(bh);
	return err;
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
	dd_inode->i_attrs |= ATTR_ARCH;
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

	// Index of cluster entry in table.
	const unsigned cluster_no = dd_inode->i_logstart;
	// How many cluster indices fit in one cluster, in table.
	const unsigned cluster_idx_per_cluster = sbi->cluster_size / 4u;
	// Cluster of table on which `cluster_no` lays.
	const unsigned table_cluster_no_containing_cluster_no =
		cluster_no / cluster_idx_per_cluster;
	// Index of block on the cluster, on which `cluster_no` lays.
	const unsigned block_no_containing_cluster_no =
		(cluster_no % cluster_idx_per_cluster) / sb->sec_per_clus;
	// Index of block on device, on which `cluster_no` lays.
	// Calculated:
	//    1 cluster for boot sector * sec_per_clus
	//    + table_cluster_no_containing_cluster_no * sec_per_clus
	//    +  block_no_containing_cluster_no
	const unsigned device_block_no_containing_cluster_no =
		sb->sec_per_clus +
		table_cluster_no_containing_cluster_no * sb->sec_per_clus +
		block_no_containing_cluster_no;
	// Cluster index on the block
	const unsigned cluster_idx_on_block =
		cluster_no % (sb->s_blocksize / 4u);

	lock_table(sbi);

	// Read the block
	bh = sb_bread(sb, device_block_no_containing_cluster_no);
	if (!bh) {
		dd_error("unable to read inode block for updating (i_pos %lld)",
			 i_pos);
		return -EIO;
	}

	__u32 *cluster_index_ptr = (__u32 *)(bh->b_data) + cluster_idx_on_block;

	// Finally, write cluster as unused:
	*cluster_index_ptr = DDFS_CLUSTER_UNUSED;

	unlock_table(sbi);

	return 0;
}

void ddfs_truncate_blocks(struct inode *inode, loff_t offset)
{
	struct ddfs_sb_info *sbi = DDFS_SB(inode->i_sb);
	int nr_clusters;

	/*
	 * This protects against truncating a file bigger than it was then
	 * trying to write into the hole.
	 */
	if (MSDOS_I(inode)->mmu_private > offset)
		MSDOS_I(inode)->mmu_private = offset;

	nr_clusters = (offset + (sbi->cluster_size - 1)) / sbi->cluster_size;

	fat_free(inode, nr_clusters);
	fat_flush_inodes(inode->i_sb, inode, NULL);
}

static void ddfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);

	fat_truncate_blocks(inode, 0);

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
	struct msdos_sb_info *sbi = MSDOS_SB(sb);

	fat_set_state(sb, 0, 0);

	iput(sbi->fsinfo_inode);
	iput(sbi->fat_inode);

	call_rcu(&sbi->rcu, delayed_free);
}

static int ddfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	/* If the count of free cluster is still unknown, counts it here. */
	if (sbi->free_clusters == -1 || !sbi->free_clus_valid) {
		int err = fat_count_free_clusters(dentry->d_sb);
		if (err)
			return err;
	}

	buf->f_type = dentry->d_sb->s_magic;
	buf->f_bsize = sbi->cluster_size;
	buf->f_blocks = sbi->max_cluster - FAT_START_ENT;
	buf->f_bfree = sbi->free_clusters;
	buf->f_bavail = sbi->free_clusters;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen =
		(sbi->options.isvfat ? FAT_LFN_LEN : 12) * NLS_MAX_CHARSET_SIZE;

	return 0;
}

static int ddfs_remount(struct super_block *sb, int *flags, char *data)
{
	bool new_rdonly;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	*flags |= SB_NODIRATIME | (sbi->options.isvfat ? 0 : SB_NOATIME);

	sync_filesystem(sb);

	/* make sure we update state on remount. */
	new_rdonly = *flags & SB_RDONLY;
	if (new_rdonly != sb_rdonly(sb)) {
		if (new_rdonly)
			fat_set_state(sb, 0, 0);
		else
			fat_set_state(sb, 1, 1);
	}
	return 0;
}

static int ddfs_show_options(struct seq_file *m, struct dentry *root);
static const struct super_operations ddfs_sops = {
	.alloc_inode = ddfs_alloc_inode,
	.free_inode = ddfs_free_inode,
	.write_inode = ddfs_write_inode,
	.evict_inode = ddfs_evict_inode,
	.put_super = ddfs_put_super,
	.statfs = ddfs_statfs,
	.remount_fs = ddfs_remount,

	.show_options = ddfs_show_options,
};

static int ddfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct msdos_sb_info *sbi = MSDOS_SB(root->d_sb);
	struct fat_mount_options *opts = &sbi->options;
	int isvfat = opts->isvfat;

	if (!uid_eq(opts->fs_uid, GLOBAL_ROOT_UID))
		seq_printf(m, ",uid=%u",
			   from_kuid_munged(&init_user_ns, opts->fs_uid));
	if (!gid_eq(opts->fs_gid, GLOBAL_ROOT_GID))
		seq_printf(m, ",gid=%u",
			   from_kgid_munged(&init_user_ns, opts->fs_gid));
	seq_printf(m, ",fmask=%04o", opts->fs_fmask);
	seq_printf(m, ",dmask=%04o", opts->fs_dmask);
	if (opts->allow_utime)
		seq_printf(m, ",allow_utime=%04o", opts->allow_utime);
	if (sbi->nls_disk)
		/* strip "cp" prefix from displayed option */
		seq_printf(m, ",codepage=%s", &sbi->nls_disk->charset[2]);
	if (isvfat) {
		if (sbi->nls_io)
			seq_printf(m, ",iocharset=%s", sbi->nls_io->charset);

		switch (opts->shortname) {
		case VFAT_SFN_DISPLAY_WIN95 | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=win95");
			break;
		case VFAT_SFN_DISPLAY_WINNT | VFAT_SFN_CREATE_WINNT:
			seq_puts(m, ",shortname=winnt");
			break;
		case VFAT_SFN_DISPLAY_WINNT | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=mixed");
			break;
		case VFAT_SFN_DISPLAY_LOWER | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=lower");
			break;
		default:
			seq_puts(m, ",shortname=unknown");
			break;
		}
	}
	if (opts->name_check != 'n')
		seq_printf(m, ",check=%c", opts->name_check);
	if (opts->usefree)
		seq_puts(m, ",usefree");
	if (opts->quiet)
		seq_puts(m, ",quiet");
	if (opts->showexec)
		seq_puts(m, ",showexec");
	if (opts->sys_immutable)
		seq_puts(m, ",sys_immutable");
	if (!isvfat) {
		if (opts->dotsOK)
			seq_puts(m, ",dotsOK=yes");
		if (opts->nocase)
			seq_puts(m, ",nocase");
	} else {
		if (opts->utf8)
			seq_puts(m, ",utf8");
		if (opts->unicode_xlate)
			seq_puts(m, ",uni_xlate");
		if (!opts->numtail)
			seq_puts(m, ",nonumtail");
		if (opts->rodir)
			seq_puts(m, ",rodir");
	}
	if (opts->flush)
		seq_puts(m, ",flush");
	if (opts->tz_set) {
		if (opts->time_offset)
			seq_printf(m, ",time_offset=%d", opts->time_offset);
		else
			seq_puts(m, ",tz=UTC");
	}
	if (opts->errors == FAT_ERRORS_CONT)
		seq_puts(m, ",errors=continue");
	else if (opts->errors == FAT_ERRORS_PANIC)
		seq_puts(m, ",errors=panic");
	else
		seq_puts(m, ",errors=remount-ro");
	if (opts->nfs == FAT_NFS_NOSTALE_RO)
		seq_puts(m, ",nfs=nostale_ro");
	else if (opts->nfs)
		seq_puts(m, ",nfs=stale_rw");
	if (opts->discard)
		seq_puts(m, ",discard");
	if (opts->dos1xfloppy)
		seq_puts(m, ",dos1xfloppy");

	return 0;
}

static struct dentry *ddfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
					int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    fat_nfs_get_inode);
}

static struct dentry *ddfs_fh_to_parent(struct super_block *sb, struct fid *fid,
					int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    fat_nfs_get_inode);
}

static struct dentry *ddfs_get_parent(struct dentry *child_dir)
{
	struct super_block *sb = child_dir->d_sb;
	struct buffer_head *bh = NULL;
	struct msdos_dir_entry *de;
	struct inode *parent_inode = NULL;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);

	if (!fat_get_dotdot_entry(d_inode(child_dir), &bh, &de)) {
		int parent_logstart = fat_get_start(sbi, de);
		parent_inode = fat_dget(sb, parent_logstart);
		if (!parent_inode && sbi->options.nfs == FAT_NFS_NOSTALE_RO)
			parent_inode = fat_rebuild_parent(sb, parent_logstart);
	}
	brelse(bh);

	return d_obtain_alias(parent_inode);
}

const struct export_operations fat_export_ops = {
	.fh_to_dentry = ddfs_fh_to_dentry,
	.fh_to_parent = ddfs_fh_to_parent,
	.get_parent = ddfs_get_parent,
};

static int ddfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct fat_slot_info sinfo;
	struct timespec64 ts;
	int err;

	mutex_lock(&MSDOS_SB(sb)->s_lock);

	ts = current_time(dir);
	err = vfat_add_entry(dir, &dentry->d_name, 0, 0, &ts, &sinfo);
	if (err)
		goto out;
	inode_inc_iversion(dir);

	inode = fat_build_inode(sb, sinfo.de, sinfo.i_pos);
	brelse(sinfo.bh);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}
	inode_inc_iversion(inode);
	fat_truncate_time(inode, &ts, S_ATIME | S_CTIME | S_MTIME);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	d_instantiate(dentry, inode);
out:
	mutex_unlock(&MSDOS_SB(sb)->s_lock);
	return err;
}

static struct dentry *ddfs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct fat_slot_info sinfo;
	struct inode *inode;
	struct dentry *alias;
	int err;

	mutex_lock(&MSDOS_SB(sb)->s_lock);

	err = vfat_find(dir, &dentry->d_name, &sinfo);
	if (err) {
		if (err == -ENOENT) {
			inode = NULL;
			goto out;
		}
		goto error;
	}

	inode = fat_build_inode(sb, sinfo.de, sinfo.i_pos);
	brelse(sinfo.bh);
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
		if (!S_ISDIR(inode->i_mode))
			d_move(alias, dentry);
		iput(inode);
		mutex_unlock(&MSDOS_SB(sb)->s_lock);
		return alias;
	} else
		dput(alias);

out:
	mutex_unlock(&MSDOS_SB(sb)->s_lock);
	if (!inode)
		vfat_d_version_set(dentry, inode_query_iversion(dir));
	return d_splice_alias(inode, dentry);
error:
	mutex_unlock(&MSDOS_SB(sb)->s_lock);
	return ERR_PTR(err);
}

static int ddfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = dir->i_sb;
	struct fat_slot_info sinfo;
	int err;

	mutex_lock(&MSDOS_SB(sb)->s_lock);

	err = vfat_find(dir, &dentry->d_name, &sinfo);
	if (err)
		goto out;

	err = fat_remove_entries(dir, &sinfo); /* and releases bh */
	if (err)
		goto out;
	clear_nlink(inode);
	fat_truncate_time(inode, NULL, S_ATIME | S_MTIME);
	fat_detach(inode);
	vfat_d_version_set(dentry, inode_query_iversion(dir));
out:
	mutex_unlock(&MSDOS_SB(sb)->s_lock);

	return err;
}

static int ddfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct fat_slot_info sinfo;
	struct timespec64 ts;
	int err, cluster;

	mutex_lock(&MSDOS_SB(sb)->s_lock);

	ts = current_time(dir);
	cluster = fat_alloc_new_dir(dir, &ts);
	if (cluster < 0) {
		err = cluster;
		goto out;
	}
	err = vfat_add_entry(dir, &dentry->d_name, 1, cluster, &ts, &sinfo);
	if (err)
		goto out_free;
	inode_inc_iversion(dir);
	inc_nlink(dir);

	inode = fat_build_inode(sb, sinfo.de, sinfo.i_pos);
	brelse(sinfo.bh);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		/* the directory was completed, just return a error */
		goto out;
	}
	inode_inc_iversion(inode);
	set_nlink(inode, 2);
	fat_truncate_time(inode, &ts, S_ATIME | S_CTIME | S_MTIME);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	d_instantiate(dentry, inode);

	mutex_unlock(&MSDOS_SB(sb)->s_lock);
	return 0;

out_free:
	fat_free_clusters(dir, cluster);
out:
	mutex_unlock(&MSDOS_SB(sb)->s_lock);
	return err;
}

static int ddfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = dir->i_sb;
	struct fat_slot_info sinfo;
	int err;

	mutex_lock(&MSDOS_SB(sb)->s_lock);

	err = fat_dir_empty(inode);
	if (err)
		goto out;
	err = vfat_find(dir, &dentry->d_name, &sinfo);
	if (err)
		goto out;

	err = fat_remove_entries(dir, &sinfo); /* and releases bh */
	if (err)
		goto out;
	drop_nlink(dir);

	clear_nlink(inode);
	fat_truncate_time(inode, NULL, S_ATIME | S_MTIME);
	fat_detach(inode);
	vfat_d_version_set(dentry, inode_query_iversion(dir));
out:
	mutex_unlock(&MSDOS_SB(sb)->s_lock);

	return err;
}

static int ddfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags)
{
	struct buffer_head *dotdot_bh;
	struct msdos_dir_entry *dotdot_de;
	struct inode *old_inode, *new_inode;
	struct fat_slot_info old_sinfo, sinfo;
	struct timespec64 ts;
	loff_t new_i_pos;
	int err, is_dir, update_dotdot, corrupt = 0;
	struct super_block *sb = old_dir->i_sb;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	old_sinfo.bh = sinfo.bh = dotdot_bh = NULL;
	old_inode = d_inode(old_dentry);
	new_inode = d_inode(new_dentry);
	mutex_lock(&MSDOS_SB(sb)->s_lock);
	err = vfat_find(old_dir, &old_dentry->d_name, &old_sinfo);
	if (err)
		goto out;

	is_dir = S_ISDIR(old_inode->i_mode);
	update_dotdot = (is_dir && old_dir != new_dir);
	if (update_dotdot) {
		if (fat_get_dotdot_entry(old_inode, &dotdot_bh, &dotdot_de)) {
			err = -EIO;
			goto out;
		}
	}

	ts = current_time(old_dir);
	if (new_inode) {
		if (is_dir) {
			err = fat_dir_empty(new_inode);
			if (err)
				goto out;
		}
		new_i_pos = MSDOS_I(new_inode)->i_pos;
		fat_detach(new_inode);
	} else {
		err = vfat_add_entry(new_dir, &new_dentry->d_name, is_dir, 0,
				     &ts, &sinfo);
		if (err)
			goto out;
		new_i_pos = sinfo.i_pos;
	}
	inode_inc_iversion(new_dir);

	fat_detach(old_inode);
	fat_attach(old_inode, new_i_pos);
	if (IS_DIRSYNC(new_dir)) {
		err = fat_sync_inode(old_inode);
		if (err)
			goto error_inode;
	} else
		mark_inode_dirty(old_inode);

	if (update_dotdot) {
		fat_set_start(dotdot_de, MSDOS_I(new_dir)->i_logstart);
		mark_buffer_dirty_inode(dotdot_bh, old_inode);
		if (IS_DIRSYNC(new_dir)) {
			err = sync_dirty_buffer(dotdot_bh);
			if (err)
				goto error_dotdot;
		}
		drop_nlink(old_dir);
		if (!new_inode)
			inc_nlink(new_dir);
	}

	err = fat_remove_entries(old_dir, &old_sinfo); /* and releases bh */
	old_sinfo.bh = NULL;
	if (err)
		goto error_dotdot;
	inode_inc_iversion(old_dir);
	fat_truncate_time(old_dir, &ts, S_CTIME | S_MTIME);
	if (IS_DIRSYNC(old_dir))
		(void)fat_sync_inode(old_dir);
	else
		mark_inode_dirty(old_dir);

	if (new_inode) {
		drop_nlink(new_inode);
		if (is_dir)
			drop_nlink(new_inode);
		fat_truncate_time(new_inode, &ts, S_CTIME);
	}
out:
	brelse(sinfo.bh);
	brelse(dotdot_bh);
	brelse(old_sinfo.bh);
	mutex_unlock(&MSDOS_SB(sb)->s_lock);

	return err;

error_dotdot:
	/* data cluster is shared, serious corruption */
	corrupt = 1;

	if (update_dotdot) {
		fat_set_start(dotdot_de, MSDOS_I(old_dir)->i_logstart);
		mark_buffer_dirty_inode(dotdot_bh, old_inode);
		corrupt |= sync_dirty_buffer(dotdot_bh);
	}
error_inode:
	fat_detach(old_inode);
	fat_attach(old_inode, old_sinfo.i_pos);
	if (new_inode) {
		fat_attach(new_inode, new_i_pos);
		if (corrupt)
			corrupt |= fat_sync_inode(new_inode);
	} else {
		/*
		 * If new entry was not sharing the data cluster, it
		 * shouldn't be serious corruption.
		 */
		int err2 = fat_remove_entries(new_dir, &sinfo);
		if (corrupt)
			corrupt |= err2;
		sinfo.bh = NULL;
	}
	if (corrupt < 0) {
		fat_fs_error(new_dir->i_sb,
			     "%s: Filesystem corrupted (i_pos %lld)", __func__,
			     sinfo.i_pos);
	}
	goto out;
}

int ddfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct msdos_sb_info *sbi = MSDOS_SB(dentry->d_sb);
	struct inode *inode = d_inode(dentry);
	unsigned int ia_valid;
	int error;

	/* Check for setting the inode time. */
	ia_valid = attr->ia_valid;
	if (ia_valid & TIMES_SET_FLAGS) {
		if (fat_allow_set_time(sbi, inode))
			attr->ia_valid &= ~TIMES_SET_FLAGS;
	}

	error = setattr_prepare(dentry, attr);
	attr->ia_valid = ia_valid;
	if (error) {
		if (sbi->options.quiet)
			error = 0;
		goto out;
	}

	/*
	 * Expand the file. Since inode_setattr() updates ->i_size
	 * before calling the ->truncate(), but FAT needs to fill the
	 * hole before it. XXX: this is no longer true with new truncate
	 * sequence.
	 */
	if (attr->ia_valid & ATTR_SIZE) {
		inode_dio_wait(inode);

		if (attr->ia_size > inode->i_size) {
			error = fat_cont_expand(inode, attr->ia_size);
			if (error || attr->ia_valid == ATTR_SIZE)
				goto out;
			attr->ia_valid &= ~ATTR_SIZE;
		}
	}

	if (((attr->ia_valid & ATTR_UID) &&
	     (!uid_eq(attr->ia_uid, sbi->options.fs_uid))) ||
	    ((attr->ia_valid & ATTR_GID) &&
	     (!gid_eq(attr->ia_gid, sbi->options.fs_gid))) ||
	    ((attr->ia_valid & ATTR_MODE) && (attr->ia_mode & ~FAT_VALID_MODE)))
		error = -EPERM;

	if (error) {
		if (sbi->options.quiet)
			error = 0;
		goto out;
	}

	/*
	 * We don't return -EPERM here. Yes, strange, but this is too
	 * old behavior.
	 */
	if (attr->ia_valid & ATTR_MODE) {
		if (fat_sanitize_mode(sbi, inode, &attr->ia_mode) < 0)
			attr->ia_valid &= ~ATTR_MODE;
	}

	if (attr->ia_valid & ATTR_SIZE) {
		error = fat_block_truncate_page(inode, attr->ia_size);
		if (error)
			goto out;
		down_write(&MSDOS_I(inode)->truncate_lock);
		truncate_setsize(inode, attr->ia_size);
		fat_truncate_blocks(inode, attr->ia_size);
		up_write(&MSDOS_I(inode)->truncate_lock);
	}

	/*
	 * setattr_copy can't truncate these appropriately, so we'll
	 * copy them ourselves
	 */
	if (attr->ia_valid & ATTR_ATIME)
		fat_truncate_time(inode, &attr->ia_atime, S_ATIME);
	if (attr->ia_valid & ATTR_CTIME)
		fat_truncate_time(inode, &attr->ia_ctime, S_CTIME);
	if (attr->ia_valid & ATTR_MTIME)
		fat_truncate_time(inode, &attr->ia_mtime, S_MTIME);
	attr->ia_valid &= ~(ATTR_ATIME | ATTR_CTIME | ATTR_MTIME);

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
out:
	return error;
}
EXPORT_SYMBOL_GPL(ddfs_setattr);

int ddfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
		 unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	generic_fillattr(inode, stat);
	stat->blksize = MSDOS_SB(inode->i_sb)->cluster_size;

	if (MSDOS_SB(inode->i_sb)->options.nfs == FAT_NFS_NOSTALE_RO) {
		/* Use i_pos for ino. This is used as fileid of nfs. */
		stat->ino = fat_i_pos_read(MSDOS_SB(inode->i_sb), inode);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ddfs_getattr);

int ddfs_update_time(struct inode *inode, struct timespec64 *now, int flags)
{
	int iflags = I_DIRTY_TIME;
	bool dirty = false;

	if (inode->i_ino == MSDOS_ROOT_INO)
		return 0;

	fat_truncate_time(inode, now, flags);
	if (flags & S_VERSION)
		dirty = inode_maybe_inc_iversion(inode, false);
	if ((flags & (S_ATIME | S_CTIME | S_MTIME)) &&
	    !(inode->i_sb->s_flags & SB_LAZYTIME))
		dirty = true;

	if (dirty)
		iflags |= I_DIRTY_SYNC;
	__mark_inode_dirty(inode, iflags);
	return 0;
}
EXPORT_SYMBOL_GPL(ddfs_update_time);

static const struct inode_operations vfat_dir_inode_operations = {
	.create = ddfs_create,
	.lookup = ddfs_lookup,
	.unlink = ddfs_unlink,
	.mkdir = ddfs_mkdir,
	.rmdir = ddfs_rmdir,
	.rename = ddfs_rename,
	.setattr = ddfs_setattr,
	.getattr = ddfs_getattr,
	.update_time = ddfs_update_time,
};

static int ddfs_revalidate(struct dentry *dentry, unsigned int flags)
{
	if (flags & LOOKUP_RCU)
		return -ECHILD;

	/* This is not negative dentry. Always valid. */
	if (d_really_is_positive(dentry))
		return 1;
	return vfat_revalidate_shortname(dentry);
}

static int ddfs_hash(const struct dentry *dentry, struct qstr *qstr)
{
	qstr->hash =
		full_name_hash(dentry, qstr->name, vfat_striptail_len(qstr));
	return 0;
}

static int ddfs_cmp(const struct dentry *dentry, unsigned int len,
		    const char *str, const struct qstr *name)
{
	unsigned int alen, blen;

	/* A filename cannot end in '.' or we treat it like it has none */
	alen = vfat_striptail_len(name);
	blen = __vfat_striptail_len(len, str);
	if (alen == blen) {
		if (strncmp(name->name, str, alen) == 0)
			return 0;
	}
	return 1;
}

static const struct dentry_operations ddfs_dentry_ops = {
	.d_revalidate = ddfs_revalidate,
	.d_hash = ddfs_hash,
	.d_compare = ddfs_cmp,
};

struct ddfs_boot_sector {
	__u16 sector_size;
	__u8 sectors_per_cluster;
	__u32 number_of_clusters;
};

long ddfs_read_boot_sector(struct super_block *sb, void *data,
			   struct ddfs_boot_sector *boot_sector)
{
	memcpy(boot_sector, data, sizeof(struct ddfs_boot_sector));
	return 0;
}

void log_boot_sector(struct ddfs_boot_sector *boot_sector)
{
	dd_print("sector_size: %u, s/c: %u, number_of_clusters: %u",
		 boot_sector->sector_size, boot_sector->sectors_per_cluster,
		 boot_sector->number_of_clusters);
}

unsigned int calculate_data_offset(struct msdos_sb_info *sbi)
{
	unsigned int first_data_cluster = 1; // 1 for boot sector
	unsigned int table_end = sbi->table_offset + sbi->table_size;

	first_data_cluster += table_end / sbi->cluster_size;

	if (table_end % sbi->cluster_size != 0) {
		++first_data_cluster;
	}

	return first_data_cluster * sbi->cluster_size;
}

static int ddfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct msdos_sb_info *sbi;
	long error;
	struct buffer_head *bh;
	struct ddfs_boot_sector boot_sector;

	sbi = kzalloc(sizeof(struct ddfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;

	sb->s_flags |= SB_NODIRATIME;
	sb->s_magic = DDFS_SUPER_MAGIC;
	sb->s_op = &fat_sops;
	sb->s_export_op = &ddfs_export_ops;
	sb->s_time_gran = 1;
	mutex_init(&sbi->nfs_build_inode_lock);
	ratelimit_state_init(&sbi->ratelimit, DEFAULT_RATELIMIT_INTERVAL,
			     DEFAULT_RATELIMIT_BURST);

	error = parse_options(sb, data, isvfat, silent, &debug, &sbi->options);
	if (error) {
		goto out_fail;
	}

	sb->s_fs_info->dir_ops = &ddfs_dir_inode_operations;
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

	sbi->sec_per_clus = boot_sector.sectors_per_cluster;

	mutex_init(&sbi->s_lock);
	sbi->cluster_size = sb->s_blocksize * sbi->sec_per_clus;
	sbi->number_of_table_entries = boot_sector.number_of_clusters;
	sbi->table_start = sbi->cluster_size;
	sbi->table_size =
		boot_sector.number_of_clusters * sizeof(struct ddfs_dir_entry);
	sbi->data_offset = calculate_data_offset(sbi);
	sbi->blocksize = sb->s_blocksize;

	sbi->entries_per_cluster =
		sbi->cluster_size / sizeof(DDFS_DIR_ENTRY_SIZE_TYPE);

	sbi->name_entries_offset = = 0;
	sbi->attributes_entries_offset = =
		sbi->entries_per_cluster * DDFS_DIR_ENTRY_NAME_CHARS_IN_PLACE;
	sbi->size_entries_offset =
		sbi->attributes_entries_offset +
		sbi->entries_per_cluster *
			sizeof(DDFS_DIR_ENTRY_ATTRIBUTES_TYPE);
	sbi->first_cluster_entries_offset =
		sbi->size_entries_offset +
		sbi->entries_per_cluster * sizeof(DDFS_DIR_ENTRY_SIZE_TYPE);

	return -EINVAL;

out_fail:
	sb->s_fs_info = NULL;
	kfree(sbi);
	return error;
}

static struct dentry *ddfs_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name, void *data)
{
	dd_print("init_ddfs_fs\n");
	// return mount_bdev(fs_type, flags, dev_name, data, ddfs_fill_super);
	return ERR_PTR(-EINVAL);
}

static struct file_system_type ddfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "ddfs",
	.mount = ddfs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};

static int __init init_ddfs_fs(void)
{
	dd_print("init_ddfs_fs\n");
	return register_filesystem(&ddfs_fs_type);
}

static void __exit exit_ddfs_fs(void)
{
	dd_print("exit_ddfs_fs\n");
	unregister_filesystem(&ddfs_fs_type);
}

MODULE_ALIAS_FS("ddfs");

module_init(init_ddfs_fs);
module_exit(exit_ddfs_fs);
